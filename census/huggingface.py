"""Dynamic Hugging Face models, datasets, Spaces, Kernels, collections, and buckets."""
from __future__ import annotations

import concurrent.futures as cf
import hashlib
import posixpath
import re
import urllib.parse
from typing import Any

from .common import http_probe, paginate_json, request_bytes, request_json, token_header

HF_ORG = "SZLHOLDINGS"
HF = "https://huggingface.co"
SHA40 = re.compile(r"^[0-9a-f]{40}$")
WEIGHT_SUFFIXES = (
    ".safetensors",
    ".gguf",
    ".bin",
    ".pt",
    ".pth",
    ".onnx",
    ".ckpt",
)
ESTIMATOR_SUFFIXES = (".joblib", ".pkl", ".pickle")
EMBEDDING_ARTIFACTS = {"vectors.npz"}
NO_MODEL_ARTIFACT_CONTRACTS = {"huggingface-kernel"}


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


def classify_model_contract(paths: list[str]) -> str:
    """Classify the repository's declared artifact shape from observed paths."""
    names = {path.lower() for path in paths}
    basenames = {path.rsplit("/", 1)[-1] for path in names}
    has_kernel = "build.toml" in names and any(
        path.startswith("build/torch-universal/") for path in names
    )
    has_estimator = any(name.endswith(ESTIMATOR_SUFFIXES) for name in names)
    has_embedding = bool(basenames & EMBEDDING_ARTIFACTS)
    has_gguf = any(name.endswith(".gguf") for name in names)
    has_safetensors = any(name.endswith(".safetensors") for name in names)
    top_level_names = {name for name in names if "/" not in name}
    has_top_level_model = any(
        name
        in {
            "model.safetensors",
            "model.safetensors.index.json",
            "pytorch_model.bin",
            "pytorch_model.bin.index.json",
        }
        or (name.startswith("model-") and name.endswith(".safetensors"))
        or (name.startswith("pytorch_model-") and name.endswith(".bin"))
        for name in top_level_names
    )
    has_adapter = (
        "adapter_config.json" in names
        or "adapter_model.safetensors" in names
        or any(name.endswith("/adapter_model.safetensors") for name in names)
    )
    has_operational_payload = (
        "a11oy-metadata.json" in names
        or "payloads/deploy/manifest.json" in names
    )

    if has_operational_payload:
        return "operational-payload"
    if has_gguf:
        return "gguf"
    if "base_model_manifest.json" in names and has_estimator:
        return "recipe-with-estimator"
    if has_kernel and has_safetensors:
        return "kernel-with-torch-surrogate"
    if has_kernel and has_estimator:
        return "kernel-with-estimator"
    if has_kernel and has_embedding:
        return "kernel-with-embedding-index"
    if has_kernel:
        return "huggingface-kernel"
    if has_top_level_model and "config.json" in names:
        return "transformers-checkpoint"
    if has_adapter:
        return "peft-adapter"
    if has_estimator:
        return "serialized-estimator"
    if any(name.endswith(WEIGHT_SUFFIXES) for name in names):
        return "model-artifact"
    return "unclassified"


def _payload_file_path(path: str) -> str | None:
    """Return a safe repository path rooted at ``payloads/deploy``."""
    normalized = posixpath.normpath(str(path).replace("\\", "/")).lstrip("/")
    if not normalized or normalized == "." or normalized.startswith("../"):
        return None
    if normalized.startswith("payloads/deploy/"):
        return normalized
    return f"payloads/deploy/{normalized}"


def verify_operational_payload(
    repo_id: str,
    revision: str | None,
    repo_paths: list[str],
) -> dict[str, Any]:
    """Verify every file declared by an operational payload manifest.

    The check is bound to the model revision and fails closed on missing files,
    byte-size drift, digest drift, malformed entries, or unavailable evidence.
    """
    base = {
        "payload_manifest_state": "unknown",
        "payload_manifest_declared_files": 0,
        "payload_manifest_verified_files": 0,
        "payload_manifest_missing_files": [],
        "payload_manifest_mismatched_files": [],
        "payload_manifest_aggregate_verified": False,
        "payload_manifest_error": None,
    }
    if not revision:
        return {**base, "payload_manifest_error": "repository revision unavailable"}

    manifest_path = "payloads/deploy/MANIFEST.json"
    manifest_url = (
        f"{HF}/{urllib.parse.quote(repo_id, safe='/')}/resolve/"
        f"{urllib.parse.quote(revision, safe='')}/{manifest_path}"
    )
    raw, _, error = request_bytes(
        manifest_url,
        headers=hf_headers(),
        timeout=20,
        retries=1,
    )
    if error or raw is None:
        return {
            **base,
            "payload_manifest_error": f"manifest unavailable: {error or 'empty body'}",
        }
    try:
        import json

        manifest = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        return {**base, "payload_manifest_error": f"invalid manifest JSON: {exc}"}

    entries = manifest.get("files") if isinstance(manifest, dict) else None
    if not isinstance(entries, list):
        return {**base, "payload_manifest_error": "manifest files must be a list"}

    aggregate_input = "\n".join(
        f"{entry.get('path')}\0{entry.get('size')}\0{entry.get('sha256')}"
        for entry in entries
        if isinstance(entry, dict)
    ).encode("utf-8")
    recorded_aggregate = str(manifest.get("aggregateSha256") or "").lower()
    aggregate_verified = (
        len(recorded_aggregate) == 64
        and hashlib.sha256(aggregate_input).hexdigest() == recorded_aggregate
    )

    observed = set(repo_paths)
    missing: list[str] = []
    mismatched: list[str] = []
    verified = 0
    invalid_entries = 0
    for entry in entries:
        if not isinstance(entry, dict):
            invalid_entries += 1
            continue
        declared_path = entry.get("path")
        full_path = _payload_file_path(str(declared_path or ""))
        expected_sha = str(entry.get("sha256") or "").lower()
        expected_size = entry.get("size")
        if (
            full_path is None
            or len(expected_sha) != 64
            or not all(char in "0123456789abcdef" for char in expected_sha)
            or not isinstance(expected_size, int)
            or expected_size < 0
        ):
            invalid_entries += 1
            continue
        if full_path not in observed:
            missing.append(full_path)
            continue
        file_url = (
            f"{HF}/{urllib.parse.quote(repo_id, safe='/')}/resolve/"
            f"{urllib.parse.quote(revision, safe='')}/"
            f"{urllib.parse.quote(full_path, safe='/')}"
        )
        body, _, file_error = request_bytes(
            file_url,
            headers=hf_headers(),
            timeout=20,
            retries=1,
        )
        if file_error or body is None:
            mismatched.append(f"{full_path}:unavailable")
            continue
        actual_sha = hashlib.sha256(body).hexdigest()
        if len(body) != expected_size or actual_sha != expected_sha:
            mismatched.append(full_path)
            continue
        verified += 1

    declared_count = len(entries)
    recorded_count = manifest.get("fileCount") if isinstance(manifest, dict) else None
    count_mismatch = recorded_count != declared_count
    version_mismatch = manifest.get("manifestVersion") != 1
    incomplete = bool(
        missing
        or mismatched
        or invalid_entries
        or count_mismatch
        or version_mismatch
        or not aggregate_verified
    )
    return {
        **base,
        "payload_manifest_state": "incomplete" if incomplete else "verified",
        "payload_manifest_declared_files": declared_count,
        "payload_manifest_verified_files": verified,
        "payload_manifest_missing_files": sorted(missing),
        "payload_manifest_mismatched_files": sorted(mismatched),
        "payload_manifest_aggregate_verified": aggregate_verified,
        "payload_manifest_error": (
            "; ".join(
                value
                for value in (
                    f"{invalid_entries} invalid entries" if invalid_entries else None,
                    "fileCount does not match files" if count_mismatch else None,
                    "manifestVersion is not 1" if version_mismatch else None,
                    "aggregateSha256 does not match files" if not aggregate_verified else None,
                )
                if value
            )
            or None
        ),
    }


def normalize_hf_repo(item: dict[str, Any], kind: str) -> dict[str, Any]:
    repo_id = str(
        item.get("id")
        or item.get("modelId")
        or item.get("datasetId")
        or "unknown"
    )
    repo_siblings = siblings(item)
    card_data = item.get("cardData") or item.get("card_data") or {}
    if not isinstance(card_data, dict):
        card_data = {}
    tags = item.get("tags") if isinstance(item.get("tags"), list) else []
    license_declared = bool(card_data.get("license")) or any(
        str(tag).startswith("license:") for tag in tags
    )
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
        "card_present": (
            "README.md" in repo_siblings
            if item.get("siblings") is not None
            else None
        ),
        "license_declared": license_declared,
        "managed_marker_present": (
            "SZL_ESTATE_MANAGED.json" in repo_siblings
            if item.get("siblings") is not None
            else None
        ),
        "provenance_marker_present": (
            "MODEL_PROVENANCE.json" in repo_siblings
            if item.get("siblings") is not None
            else None
        ),
        "card_state": (
            "COMPLETE"
            if "README.md" in repo_siblings and license_declared
            else "INCOMPLETE"
            if item.get("siblings") is not None
            else "UNKNOWN"
        ),
        "url": f"{HF}/{repo_id}" if kind == "model" else f"{HF}/{kind}s/{repo_id}",
    }
    if kind == "model":
        weight_files = sorted(
            name for name in repo_siblings if name.lower().endswith(WEIGHT_SUFFIXES)
        )
        estimator_files = sorted(
            name for name in repo_siblings if name.lower().endswith(ESTIMATOR_SUFFIXES)
        )
        embedding_files = sorted(
            name
            for name in repo_siblings
            if name.lower().rsplit("/", 1)[-1] in EMBEDDING_ARTIFACTS
        )
        artifact_files = sorted(weight_files + estimator_files + embedding_files)
        contract = classify_model_contract(repo_siblings)
        normalized.update(
            {
                "pipeline_tag": item.get("pipeline_tag"),
                "contract": contract,
                "weight_files_observed": weight_files,
                "estimator_files_observed": estimator_files,
                "embedding_files_observed": embedding_files,
                "model_artifact_files_observed": artifact_files,
                "weight_state": (
                    "weights-present"
                    if weight_files
                    else "no-weight-file-observed"
                    if item.get("siblings") is not None
                    else "unknown"
                ),
                "artifact_state": (
                    "artifact-present"
                    if artifact_files
                    else "not-required-by-contract"
                    if contract in NO_MODEL_ARTIFACT_CONTRACTS
                    else "no-model-artifact-observed"
                    if item.get("siblings") is not None
                    else "unknown"
                ),
            }
        )
    return normalized


def normalize_model_with_integrity(item: dict[str, Any]) -> dict[str, Any]:
    normalized = normalize_hf_repo(item, "model")
    if normalized.get("contract") != "operational-payload":
        return normalized
    integrity = verify_operational_payload(
        normalized["id"],
        normalized.get("sha"),
        siblings(item),
    )
    normalized.update(integrity)
    state = integrity["payload_manifest_state"]
    normalized["artifact_state"] = (
        "payload-manifest-verified"
        if state == "verified"
        else "payload-manifest-incomplete"
        if state == "incomplete"
        else "unknown"
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


def _http_status(error: str | None) -> int:
    if error is None:
        return 200
    if error.startswith("http") and error[4:].isdigit():
        return int(error[4:])
    return 0


def _source_revision(payload: Any) -> str | None:
    """Extract only an explicit immutable source revision from build metadata."""
    if not isinstance(payload, dict):
        return None
    candidates = [
        payload.get("source_revision"),
        payload.get("source_sha"),
        payload.get("git_sha"),
        payload.get("revision"),
    ]
    for nested_key in ("build", "source", "runtime"):
        nested = payload.get(nested_key)
        if isinstance(nested, dict):
            candidates.extend(
                (
                    nested.get("source_revision"),
                    nested.get("source_sha"),
                    nested.get("git_sha"),
                    nested.get("revision"),
                )
            )
    for value in candidates:
        normalized = str(value or "").lower()
        if SHA40.fullmatch(normalized):
            return normalized
    return None


def normalize_space(item: dict[str, Any]) -> dict[str, Any]:
    repo_id = str(item.get("id") or "unknown")
    runtime = item.get("runtime") if isinstance(item.get("runtime"), dict) else {}
    root_url = space_runtime_url(item)
    root_probe = (
        http_probe(root_url)
        if root_url
        else {"http": 0, "error": "runtime URL unavailable"}
    )
    sdk = item.get("sdk")
    dynamic = sdk not in {None, "static"}
    healthz_probe = (
        http_probe(urllib.parse.urljoin(root_url, "healthz"))
        if dynamic and root_url
        else {}
    )
    healthz = healthz_probe.get("http")
    build_info = None
    build_info_error = None
    if dynamic and root_url:
        build_info, _, build_info_error = request_json(
            urllib.parse.urljoin(root_url, "api/build-info"),
            headers={"Accept": "application/json"},
            timeout=12,
            retries=0,
        )
    source_revision = _source_revision(build_info)
    stage = runtime.get("stage") or "unknown"
    reachable = 200 <= int(root_probe.get("http") or 0) < 400
    if stage != "RUNNING" or not reachable:
        operational_state = "DEGRADED"
    elif not dynamic:
        operational_state = "STATIC_REACHABLE"
    elif healthz == 200 and source_revision:
        operational_state = "OPERATIONAL_SOURCE_BOUND"
    elif healthz == 200:
        operational_state = "RUNTIME_HEALTHY_UNBOUND"
    else:
        operational_state = "REACHABLE_UNVERIFIED"

    repo_siblings = siblings(item)
    card_data = item.get("cardData") or item.get("card_data") or {}
    if not isinstance(card_data, dict):
        card_data = {}
    tags = item.get("tags") if isinstance(item.get("tags"), list) else []
    license_declared = bool(card_data.get("license")) or any(
        str(tag).startswith("license:") for tag in tags
    )
    return {
        "id": repo_id,
        "sha": item.get("sha"),
        "last_modified": item.get("lastModified"),
        "private": item.get("private"),
        "likes": item.get("likes"),
        "sdk": sdk,
        "stage": stage,
        "hardware": runtime.get("hardware") or runtime.get("requestedHardware"),
        "subdomain": item.get("subdomain"),
        "runtime_url": root_url,
        "http": root_probe.get("http"),
        "probe_error": root_probe.get("error"),
        "healthz": healthz,
        "healthz_error": healthz_probe.get("error"),
        "healthz_contract": healthz == 200,
        "build_info_http": (
            _http_status(build_info_error) if dynamic and root_url else None
        ),
        "build_info_error": build_info_error,
        "source_revision": source_revision,
        "source_binding_state": (
            "OBSERVED"
            if source_revision
            else "UNAVAILABLE"
            if dynamic
            else "NOT_APPLICABLE"
        ),
        "operational_state": operational_state,
        "card_present": (
            "README.md" in repo_siblings
            if item.get("siblings") is not None
            else None
        ),
        "license_declared": license_declared,
        "managed_marker_present": (
            "SZL_ESTATE_MANAGED.json" in repo_siblings
            if item.get("siblings") is not None
            else None
        ),
        "card_state": (
            "COMPLETE"
            if "README.md" in repo_siblings and license_declared
            else "INCOMPLETE"
            if item.get("siblings") is not None
            else "UNKNOWN"
        ),
        "url": f"{HF}/spaces/{repo_id}",
    }


def _full_kernel(item: dict[str, Any]) -> dict[str, Any]:
    repo_id = str(item.get("id") or "unknown")
    detail, _, detail_error = request_json(
        f"{HF}/api/kernels/{urllib.parse.quote(repo_id, safe='/')}",
        headers=hf_headers(),
        timeout=30,
        retries=1,
    )
    source = detail if isinstance(detail, dict) else item
    revision = str(source.get("sha") or "").lower()
    paths: set[str] | None = None
    tree_error: str | None = None
    if SHA40.fullmatch(revision):
        tree, _, tree_error = request_json(
            f"{HF}/api/kernels/{urllib.parse.quote(repo_id, safe='/')}/tree/"
            f"{revision}?recursive=true",
            headers=hf_headers(),
            timeout=45,
            retries=1,
        )
        if isinstance(tree, list):
            paths = {
                str(entry.get("path") or "")
                for entry in tree
                if isinstance(entry, dict)
                and entry.get("type") in {"file", "blob"}
                and entry.get("path")
            }
        elif tree_error is None:
            tree_error = "unexpected non-list tree payload"
    else:
        tree_error = "immutable kernel revision unavailable"

    required = {"README.md", "contract.json"}
    missing = sorted(required - (paths or set()))
    build_present = any(path.startswith("build/") for path in paths or set())
    if not build_present:
        missing.append("build/**")
    if paths is None:
        contract_state = "UNKNOWN"
    elif missing:
        contract_state = "INCOMPLETE"
    else:
        contract_state = "COMPLETE"
    return {
        "id": repo_id,
        "sha": revision if SHA40.fullmatch(revision) else None,
        "last_modified": source.get("lastModified"),
        "private": source.get("private"),
        "likes": source.get("likes"),
        "downloads_30d": source.get("downloads"),
        "metadata_state": "OBSERVED" if detail_error is None else "UNKNOWN",
        "metadata_error": detail_error,
        "tree_state": "OBSERVED" if paths is not None else "UNKNOWN",
        "tree_error": tree_error,
        "file_count_observed": len(paths) if paths is not None else None,
        "build_variants_present": build_present if paths is not None else None,
        "contract_state": contract_state,
        "contract_missing": missing,
        "selfcheck_state": "NOT_EXECUTED_BY_CENSUS",
        "url": f"{HF}/kernels/{repo_id}",
    }


def _full_bucket(item: dict[str, Any]) -> dict[str, Any]:
    bucket_id = str(item.get("id") or "unknown")
    tree, _, tree_error = request_json(
        f"{HF}/api/buckets/{urllib.parse.quote(bucket_id, safe='/')}/tree?recursive=true",
        headers=hf_headers(),
        timeout=30,
        retries=1,
    )
    paths = (
        {
            str(entry.get("path") or "")
            for entry in tree
            if isinstance(entry, dict) and entry.get("path")
        }
        if isinstance(tree, list)
        else None
    )
    return {
        "id": bucket_id,
        "private": item.get("private"),
        "created_at": item.get("createdAt"),
        "updated_at": item.get("updatedAt"),
        "size_bytes": item.get("size"),
        "total_files": item.get("totalFiles"),
        "tree_state": "OBSERVED" if paths is not None else "UNKNOWN",
        "tree_error": tree_error,
        "readme_present": "README.md" in (paths or set()),
        "documentation_state": (
            "COMPLETE"
            if paths is not None and "README.md" in paths
            else "INCOMPLETE"
            if paths is not None
            else "UNKNOWN"
        ),
        "url": f"{HF}/buckets/{bucket_id}",
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
                "cardData",
                "tags",
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
                "cardData",
                "tags",
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
                "siblings",
                "cardData",
                "tags",
            )
        ],
    )
    kernels = query(
        "/api/kernels",
        [("author", HF_ORG), ("limit", "500")],
    )
    collections = query(
        "/api/collections",
        [("owner", HF_ORG), ("sort", "lastModified"), ("limit", "100")],
    )
    return {
        "models": models,
        "datasets": datasets,
        "spaces": spaces,
        "kernels": kernels,
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
    with cf.ThreadPoolExecutor(max_workers=6) as executor:
        futures = {
            name: executor.submit(hf_paginate, path) for name, path in paths.items()
        }
        raw = {name: future.result() for name, future in futures.items()}

    models_raw, models_error = raw["models"]
    datasets_raw, datasets_error = raw["datasets"]
    spaces_raw, spaces_error = raw["spaces"]
    kernels_raw, kernels_error = raw["kernels"]
    collections_raw, collections_error = raw["collections"]
    buckets_raw, buckets_error = raw["buckets"]

    models = (
        sorted(
            (normalize_model_with_integrity(item) for item in models_raw),
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

    kernels: list[dict[str, Any]] | None = None
    if kernels_raw is not None:
        with cf.ThreadPoolExecutor(max_workers=6) as executor:
            kernels = sorted(
                executor.map(_full_kernel, kernels_raw), key=lambda value: value["id"]
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
        with cf.ThreadPoolExecutor(max_workers=4) as executor:
            buckets = sorted(
                executor.map(_full_bucket, buckets_raw),
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
        "kernels": asset_result(kernels, kernels_error),
        "collections": asset_result(collections, collections_error),
        "buckets": asset_result(buckets, buckets_error),
    }

    collection_members: dict[str, set[str]] = {
        "model": set(),
        "dataset": set(),
        "space": set(),
    }
    if collections is not None:
        for collection in collections:
            for member in collection.get("items") or []:
                member_type = str(member.get("type") or "")
                if member_type in collection_members:
                    collection_members[member_type].add(str(member.get("id") or ""))

    collection_coverage: dict[str, Any] = {}
    for plural, singular, values in (
        ("models", "model", models),
        ("datasets", "dataset", datasets),
        ("spaces", "space", spaces),
    ):
        if values is None or collections is None:
            collection_coverage[plural] = {
                "public_total": None,
                "covered": None,
                "missing": None,
            }
            continue
        public_ids = {
            str(value.get("id")) for value in values if not value.get("private")
        }
        covered = public_ids & collection_members[singular]
        collection_coverage[plural] = {
            "public_total": len(public_ids),
            "covered": len(covered),
            "missing": sorted(public_ids - covered),
        }

    return {
        "organization": HF_ORG,
        "assets": assets,
        "collection_coverage": collection_coverage,
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
            "dynamic_spaces": (
                sum(1 for space in spaces or [] if space.get("sdk") != "static")
                if spaces is not None
                else None
            ),
            "healthz_spaces": (
                sum(1 for space in spaces or [] if space.get("healthz") == 200)
                if spaces is not None
                else None
            ),
            "source_bound_spaces": (
                sum(
                    1
                    for space in spaces or []
                    if space.get("source_binding_state") == "OBSERVED"
                )
                if spaces is not None
                else None
            ),
            "operational_source_bound_spaces": (
                sum(
                    1
                    for space in spaces or []
                    if space.get("operational_state") == "OPERATIONAL_SOURCE_BOUND"
                )
                if spaces is not None
                else None
            ),
            "reachable_unverified_spaces": (
                sum(
                    1
                    for space in spaces or []
                    if space.get("operational_state") == "REACHABLE_UNVERIFIED"
                )
                if spaces is not None
                else None
            ),
            "complete_space_cards": (
                sum(1 for space in spaces or [] if space.get("card_state") == "COMPLETE")
                if spaces is not None
                else None
            ),
            "kernels_with_observed_metadata": (
                sum(
                    1
                    for kernel in kernels or []
                    if kernel.get("metadata_state") == "OBSERVED"
                )
                if kernels is not None
                else None
            ),
            "kernels_with_complete_contracts": (
                sum(
                    1
                    for kernel in kernels or []
                    if kernel.get("contract_state") == "COMPLETE"
                )
                if kernels is not None
                else None
            ),
            "documented_buckets": (
                sum(
                    1
                    for bucket in buckets or []
                    if bucket.get("documentation_state") == "COMPLETE"
                )
                if buckets is not None
                else None
            ),
            "models_with_observed_weights": (
                sum(
                    1
                    for model in models or []
                    if model.get("weight_state") == "weights-present"
                )
                if models is not None
                else None
            ),
            "models_with_observed_estimators": (
                sum(1 for model in models or [] if model.get("estimator_files_observed"))
                if models is not None
                else None
            ),
            "models_with_observed_artifacts": (
                sum(
                    1
                    for model in models or []
                    if model.get("artifact_state") == "artifact-present"
                )
                if models is not None
                else None
            ),
            "models_with_classified_contracts": (
                sum(
                    1
                    for model in models or []
                    if model.get("contract") != "unclassified"
                )
                if models is not None
                else None
            ),
            "models_with_satisfied_artifact_expectations": (
                sum(
                    1
                    for model in models or []
                    if model.get("artifact_state")
                    in {
                        "artifact-present",
                        "not-required-by-contract",
                        "payload-manifest-verified",
                    }
                )
                if models is not None
                else None
            ),
            "models_with_verified_payload_manifests": (
                sum(
                    1
                    for model in models or []
                    if model.get("payload_manifest_state") == "verified"
                )
                if models is not None
                else None
            ),
            "models_with_incomplete_payload_manifests": (
                sum(
                    1
                    for model in models or []
                    if model.get("payload_manifest_state") == "incomplete"
                )
                if models is not None
                else None
            ),
        },
    }
