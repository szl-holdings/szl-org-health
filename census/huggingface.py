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
HF_AUTH_SCHEMA = "szl.hf-authentication-evidence/v2"
HF_SCOPE_UNAVAILABLE = "UNAVAILABLE"
HF_SCOPE_IDENTITY_ONLY = "IDENTITY_ONLY"
HF_SCOPE_IDENTITY_AND_ORG = "IDENTITY_AND_ORG_ROLE_OBSERVED"
HF_SCOPE_AUTHENTICATED_BOUNDED = "AUTHENTICATED_BOUNDED"
HF_SPACE_HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
HF_ASSET_KINDS = (
    "models",
    "datasets",
    "spaces",
    "kernels",
    "collections",
    "buckets",
)
SHA40 = re.compile(r"^[0-9a-f]{40}$")
GITHUB_API = "https://api.github.com"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
GITHUB_REPOSITORY = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9_.-]*[A-Za-z0-9])?/"
    r"[A-Za-z0-9_.-]+$"
)
SOURCE_SCHEMA = "szl.deployment-source/v1"
BUILD_INFO_SCHEMAS = {
    SOURCE_SCHEMA,
    "szl.build-info/v1",
}
DEPLOYMENT_MANIFEST_SCHEMAS = {
    SOURCE_SCHEMA,
    "szl.hf-deploy-manifest/v1",
}
DEPLOYMENT_MANIFEST_PATHS = ("hf-deploy-manifest.json",)
DEPLOYMENT_WORKFLOW_MARKERS = (
    "huggingface",
    "hf-deploy",
    "hf_deploy",
    "/hf.",
    " space",
    "spaces",
    "deploy",
    "publish",
)
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


def _probe_state(error: Any) -> str:
    error_state = str(error).casefold()
    if error_state.startswith("http401"):
        return "INVALID_CREDENTIAL"
    if error_state.startswith("http403"):
        return "DENIED_OR_RESTRICTED"
    if error_state.startswith("http429"):
        return "RATE_LIMITED"
    return "REQUEST_FAILED"


def collect_hf_authentication() -> dict[str, Any]:
    """Validate whoami shape and project only bounded, non-identifying evidence."""
    headers = hf_headers()
    token_present = "Authorization" in headers
    base = {
        "schema": HF_AUTH_SCHEMA,
        "credential_present": token_present,
        "identity_authenticated": False,
        "principal_type_user_observed": False,
        "principal_id_observed": False,
        "user_identity_observed": False,
        "access_token_auth_observed": False,
        "access_token_metadata_observed": False,
        "target_organization": HF_ORG,
        "organization_type_observed": False,
        "organization_id_observed": False,
        "organization_name_match_observed": False,
        "target_organization_match_observed": False,
        "organization_membership_observed": False,
        "organization_read_role_observed": False,
        "credential_class": "UNKNOWN",
        "fine_grained_metadata_observed": False,
        "org_scope_candidate_observed": False,
        "unknown_grants_observed": False,
        "global_permissions_state": "UNAVAILABLE",
        "inventory_scope": HF_SCOPE_UNAVAILABLE,
        "probe_state": "UNAVAILABLE",
    }
    if not token_present:
        return {**base, "probe_state": "CREDENTIAL_NOT_CONFIGURED"}

    payload, _, error = request_json(
        f"{HF}/api/whoami-v2",
        headers=headers,
        timeout=15,
        retries=0,
    )
    if error:
        return {**base, "probe_state": _probe_state(error)}
    if not isinstance(payload, dict):
        return {**base, "probe_state": "INVALID_RESPONSE"}

    principal_type_user_observed = payload.get("type") == "user"
    principal_id = payload.get("id")
    principal_id_observed = isinstance(principal_id, str) and bool(principal_id.strip())
    user_identity_observed = principal_type_user_observed and principal_id_observed

    raw_auth = payload.get("auth")
    auth = raw_auth if isinstance(raw_auth, dict) else {}
    raw_access_token = auth.get("accessToken")
    access_token_metadata_observed = isinstance(raw_access_token, dict)
    access_token = raw_access_token if access_token_metadata_observed else {}
    access_token_auth_observed = (
        auth.get("type") == "access_token" and access_token_metadata_observed
    )
    token_role = access_token.get("role")
    credential_class = (
        {
            "fineGrained": "FINE_GRAINED",
            "read": "LEGACY_READ",
            "write": "LEGACY_WRITE",
        }.get(token_role, "UNKNOWN")
        if isinstance(token_role, str)
        else "UNKNOWN"
    )
    identity_authenticated = user_identity_observed and access_token_auth_observed

    organizations = payload.get("orgs")
    target_organization: dict[str, Any] | None = None
    if isinstance(organizations, list):
        for organization in organizations:
            if not isinstance(organization, dict):
                continue
            name = organization.get("name")
            organization_id = organization.get("id")
            if (
                organization.get("type") == "org"
                and isinstance(organization_id, str)
                and bool(organization_id.strip())
                and isinstance(name, str)
                and name.casefold() == HF_ORG.casefold()
            ):
                target_organization = organization
                break

    organization_type_observed = (
        target_organization is not None and target_organization.get("type") == "org"
    )
    organization_id_observed = (
        target_organization is not None
        and isinstance(target_organization.get("id"), str)
        and bool(target_organization["id"].strip())
    )
    organization_name_match_observed = (
        target_organization is not None
        and isinstance(target_organization.get("name"), str)
        and target_organization["name"].casefold() == HF_ORG.casefold()
    )
    target_organization_match_observed = target_organization is not None
    organization_role = (
        target_organization.get("roleInOrg")
        if target_organization is not None
        else None
    )
    organization_read_role_observed = isinstance(
        organization_role, str
    ) and organization_role in {"read", "contributor", "write", "admin"}
    fine_grained = (
        access_token.get("fineGrained")
        if isinstance(access_token.get("fineGrained"), dict)
        else None
    )
    scoped = fine_grained.get("scoped") if fine_grained is not None else None
    global_permissions = (
        fine_grained.get("global") if fine_grained is not None else None
    )
    fine_grained_metadata_observed = (
        credential_class == "FINE_GRAINED"
        and isinstance(scoped, list)
        and isinstance(global_permissions, list)
    )
    global_permissions_state = (
        "NONE"
        if isinstance(global_permissions, list) and not global_permissions
        else "PRESENT"
        if isinstance(global_permissions, list) and global_permissions
        else "UNAVAILABLE"
    )
    known_read_permissions = {"repo.content.read", "readRepoContent"}
    org_scope_candidate_observed = False
    unknown_grants_observed = credential_class == "FINE_GRAINED" and not isinstance(
        scoped, list
    )
    if credential_class == "FINE_GRAINED" and isinstance(scoped, list):
        for grant in scoped:
            if not isinstance(grant, dict):
                unknown_grants_observed = True
                continue
            entity = (
                grant.get("entity") if isinstance(grant.get("entity"), dict) else {}
            )
            permissions = grant.get("permissions")
            permission_set = (
                {str(value) for value in permissions}
                if isinstance(permissions, list)
                else set()
            )
            if not permission_set or not permission_set <= known_read_permissions:
                unknown_grants_observed = True
            if (
                target_organization is not None
                and entity.get("type") == "org"
                and entity.get("_id") == target_organization.get("id")
                and permission_set
                and permission_set <= known_read_permissions
            ):
                org_scope_candidate_observed = True

    identity_and_org = (
        identity_authenticated
        and target_organization_match_observed
        and organization_type_observed
        and organization_id_observed
        and organization_name_match_observed
        and organization_read_role_observed
    )
    return {
        **base,
        "identity_authenticated": identity_authenticated,
        "principal_type_user_observed": principal_type_user_observed,
        "principal_id_observed": principal_id_observed,
        "user_identity_observed": user_identity_observed,
        "access_token_auth_observed": access_token_auth_observed,
        "access_token_metadata_observed": access_token_metadata_observed,
        "organization_type_observed": organization_type_observed,
        "organization_id_observed": organization_id_observed,
        "organization_name_match_observed": organization_name_match_observed,
        "target_organization_match_observed": target_organization_match_observed,
        "organization_membership_observed": target_organization_match_observed,
        "organization_read_role_observed": organization_read_role_observed,
        "credential_class": credential_class,
        "fine_grained_metadata_observed": fine_grained_metadata_observed,
        "org_scope_candidate_observed": org_scope_candidate_observed,
        "unknown_grants_observed": unknown_grants_observed,
        "global_permissions_state": global_permissions_state,
        "inventory_scope": (
            HF_SCOPE_IDENTITY_AND_ORG
            if identity_and_org
            else HF_SCOPE_IDENTITY_ONLY
            if identity_authenticated
            else HF_SCOPE_UNAVAILABLE
        ),
        "probe_state": (
            "AUTHENTICATED" if identity_authenticated else "INVALID_RESPONSE"
        ),
    }


def finalize_hf_authentication(
    authentication: dict[str, Any], assets: dict[str, Any]
) -> dict[str, Any]:
    """Canonicalize scope, promoting only after every asset endpoint completes."""
    projected = dict(authentication)
    all_assets_complete = all(
        isinstance(assets.get(name), dict) and assets[name].get("ok") is True
        for name in HF_ASSET_KINDS
    )
    identity_valid = (
        projected.get("schema") == HF_AUTH_SCHEMA
        and projected.get("credential_present") is True
        and projected.get("identity_authenticated") is True
        and projected.get("principal_type_user_observed") is True
        and projected.get("principal_id_observed") is True
        and projected.get("user_identity_observed") is True
        and projected.get("access_token_auth_observed") is True
        and projected.get("access_token_metadata_observed") is True
        and projected.get("probe_state") == "AUTHENTICATED"
    )
    identity_and_org_valid = (
        identity_valid
        and projected.get("target_organization") == HF_ORG
        and projected.get("target_organization_match_observed") is True
        and projected.get("organization_type_observed") is True
        and projected.get("organization_id_observed") is True
        and projected.get("organization_name_match_observed") is True
        and projected.get("organization_membership_observed") is True
        and projected.get("organization_read_role_observed") is True
    )
    if not identity_valid:
        projected["inventory_scope"] = HF_SCOPE_UNAVAILABLE
    elif not identity_and_org_valid:
        projected["inventory_scope"] = HF_SCOPE_IDENTITY_ONLY
    elif all_assets_complete:
        projected["inventory_scope"] = HF_SCOPE_AUTHENTICATED_BOUNDED
    else:
        projected["inventory_scope"] = HF_SCOPE_IDENTITY_AND_ORG
    return projected


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
        "a11oy-metadata.json" in names or "payloads/deploy/manifest.json" in names
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
                    "aggregateSha256 does not match files"
                    if not aggregate_verified
                    else None,
                )
                if value
            )
            or None
        ),
    }


def normalize_hf_repo(item: dict[str, Any], kind: str) -> dict[str, Any]:
    repo_id = str(
        item.get("id") or item.get("modelId") or item.get("datasetId") or "unknown"
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
            "README.md" in repo_siblings if item.get("siblings") is not None else None
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
    raw_subdomain = item.get("subdomain")
    subdomain: str | None = None
    if raw_subdomain is None or raw_subdomain == "":
        repo_id = str(item.get("id") or "")
        if "/" in repo_id:
            owner, name = repo_id.split("/", 1)
            subdomain = f"{owner}-{name}".lower()
    elif isinstance(raw_subdomain, str):
        subdomain = raw_subdomain
    if subdomain is None or HF_SPACE_HOST_LABEL.fullmatch(subdomain) is None:
        return None
    suffix = ".static.hf.space" if item.get("sdk") == "static" else ".hf.space"
    return f"https://{subdomain}{suffix}/"


def _http_status(error: str | None) -> int:
    if error is None:
        return 200
    if error.startswith("invalid-json:"):
        # request_json only reports this after a successful HTTP response body.
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


def _first_value(payload: dict[str, Any], *paths: tuple[str, ...]) -> Any:
    for path in paths:
        value: Any = payload
        for key in path:
            if not isinstance(value, dict) or key not in value:
                value = None
                break
            value = value[key]
        if value is not None and value != "":
            return value
    return None


def _normalize_github_repository(value: Any) -> str | None:
    text = str(value or "").strip()
    if not text:
        return None
    if text.startswith(("https://", "http://")):
        parsed = urllib.parse.urlparse(text)
        if parsed.hostname not in {"github.com", "www.github.com"}:
            return None
        parts = [part for part in parsed.path.strip("/").split("/") if part]
        if len(parts) != 2:
            return None
        text = "/".join(parts)
    text = text.removesuffix(".git").strip("/")
    return text if GITHUB_REPOSITORY.fullmatch(text) else None


def _normalize_sha256(value: Any) -> str | None:
    digest = str(value or "").strip().lower()
    if digest.startswith("sha256:"):
        digest = digest[7:]
    return digest if SHA256.fullmatch(digest) else None


def _workflow_run_id(value: Any, repository: str) -> int | None:
    if isinstance(value, dict):
        value = _first_value(value, ("id",), ("run_id",), ("url",), ("html_url",))
    if isinstance(value, int) and value > 0:
        return value
    text = str(value or "").strip()
    if text.isdigit() and int(text) > 0:
        return int(text)
    if not text.startswith(("https://", "http://")):
        return None
    parsed = urllib.parse.urlparse(text)
    if parsed.hostname not in {"github.com", "www.github.com"}:
        return None
    parts = [part for part in parsed.path.strip("/").split("/") if part]
    if len(parts) != 5 or parts[2:4] != ["actions", "runs"]:
        return None
    if f"{parts[0]}/{parts[1]}".casefold() != repository.casefold():
        return None
    return int(parts[4]) if parts[4].isdigit() and int(parts[4]) > 0 else None


def _source_claim(
    payload: Any,
    *,
    evidence: str,
    schema_mode: str,
) -> tuple[dict[str, Any] | None, str | None]:
    if not isinstance(payload, dict):
        return None, f"{evidence}: JSON root must be an object"

    schema = _first_value(payload, ("schema",), ("schema_version",), ("$schema",))
    if schema_mode == "source" and schema != SOURCE_SCHEMA:
        return None, f"{evidence}: schema must be {SOURCE_SCHEMA}"
    if schema_mode == "build" and schema not in BUILD_INFO_SCHEMAS:
        return None, f"{evidence}: unsupported or missing build-info schema"
    if schema_mode == "manifest" and schema not in DEPLOYMENT_MANIFEST_SCHEMAS:
        return None, f"{evidence}: unsupported or missing deployment manifest schema"

    repository = _normalize_github_repository(
        _first_value(
            payload,
            ("source", "repository"),
            ("source", "repository_url"),
            ("source", "repo"),
            ("source_repository",),
            ("source_repo",),
            ("github_repository",),
            ("build", "source_repository"),
            ("build", "repository"),
        )
    )
    if repository is None:
        return None, f"{evidence}: valid GitHub source repository is required"

    source_revision = str(
        _first_value(
            payload,
            ("source", "commit"),
            ("source", "revision"),
            ("source", "sha"),
            ("source_revision",),
            ("source_commit",),
            ("source_sha",),
            ("git_sha",),
            ("build", "source_revision"),
            ("build", "source_commit"),
            ("build", "source_sha"),
            ("build", "git_sha"),
            ("build", "revision"),
        )
        or ""
    ).lower()
    if not SHA40.fullmatch(source_revision):
        return None, f"{evidence}: immutable 40-hex source commit is required"

    hf_revision = str(
        _first_value(
            payload,
            ("deployment", "hf_revision"),
            ("deployment", "revision"),
            ("runtime", "hf_revision"),
            ("runtime", "revision"),
            ("hf_revision",),
            ("deployed_revision",),
            ("space_revision",),
        )
        or ""
    ).lower()
    if not SHA40.fullmatch(hf_revision):
        return None, f"{evidence}: immutable 40-hex Hugging Face revision is required"

    artifact_digest = _normalize_sha256(
        _first_value(
            payload,
            ("deployment", "artifact_set_sha256"),
            ("deployment", "artifact_digest"),
            ("deployment", "artifact_sha256"),
            ("artifact_set", "sha256"),
            ("artifact_set", "digest"),
            ("artifact_set_sha256",),
            ("artifact_digest",),
            ("artifact_sha256",),
        )
    )
    if artifact_digest is None:
        return None, f"{evidence}: valid SHA-256 artifact-set digest is required"

    workflow_run = _workflow_run_id(
        _first_value(
            payload,
            ("deployment", "workflow_run"),
            ("deployment", "workflow_run_id"),
            ("deployment", "run_id"),
            ("source", "workflow_run"),
            ("source", "workflow_run_id"),
            ("workflow_run",),
            ("workflow_run_id",),
            ("deployment_run",),
        ),
        repository,
    )
    if workflow_run is None:
        return None, f"{evidence}: valid GitHub workflow run is required"

    hf_repository_value = _first_value(
        payload,
        ("deployment", "hf_repository"),
        ("deployment", "space", "repository"),
        ("deployment", "space", "id"),
        ("deployment", "space"),
        ("destination", "repository"),
        ("hf_repository",),
        ("space",),
    )
    hf_repository = (
        str(hf_repository_value).strip()
        if isinstance(hf_repository_value, str)
        else ""
    )
    if not hf_repository:
        return None, f"{evidence}: Hugging Face destination repository is required"
    return (
        {
            "evidence": evidence,
            "repository": repository,
            "source_revision": source_revision,
            "workflow_run_id": workflow_run,
            "hf_revision": hf_revision,
            "hf_repository": hf_repository,
            "artifact_sha256": artifact_digest,
        },
        None,
    )


def _read_source_document(
    url: str,
    *,
    evidence: str,
    schema_mode: str,
    headers: dict[str, str] | None = None,
) -> tuple[dict[str, Any] | None, str, str | None]:
    payload, _, error = request_json(
        url,
        headers=headers or {"Accept": "application/json"},
        timeout=12,
        retries=0,
    )
    if error:
        if error in {"http404", "http410"}:
            return None, "ABSENT", error
        if error.startswith("invalid-json:"):
            return None, "INVALID", f"{evidence}: HTTP success did not return JSON"
        return None, "UNKNOWN", f"{evidence}: {error}"
    claim, validation_error = _source_claim(
        payload,
        evidence=evidence,
        schema_mode=schema_mode,
    )
    if validation_error:
        return None, "INVALID", validation_error
    return claim, "VALID", None


def _binding_result(
    state: str,
    *,
    error: str | None,
    claim: dict[str, Any] | None = None,
    evidence: list[str] | None = None,
    build_info_http: int | None = None,
    build_info_error: str | None = None,
) -> dict[str, Any]:
    claim = claim or {}
    return {
        "source_binding_state": state,
        "source_binding_error": error,
        "source_evidence": sorted(evidence or []),
        "source_repository": claim.get("repository"),
        "source_revision": claim.get("source_revision"),
        "source_workflow_run_id": claim.get("workflow_run_id"),
        "source_hf_revision": claim.get("hf_revision"),
        "source_artifact_sha256": claim.get("artifact_sha256"),
        "build_info_http": build_info_http,
        "build_info_error": build_info_error,
    }


def _github_headers() -> dict[str, str]:
    return {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        **token_header(("GITHUB_TOKEN", "GH_TOKEN", "SZL_GITHUB_TOKEN")),
    }


def _authenticate_github_claim(
    claim: dict[str, Any],
) -> tuple[str, str | None]:
    headers = _github_headers()
    if "Authorization" not in headers:
        return "UNKNOWN", "GitHub authentication is unavailable"

    repository = claim["repository"]
    revision = claim["source_revision"]
    encoded_repository = urllib.parse.quote(repository, safe="/")
    commit, _, commit_error = request_json(
        f"{GITHUB_API}/repos/{encoded_repository}/commits/{revision}",
        headers=headers,
        timeout=20,
        retries=1,
    )
    if commit_error or not isinstance(commit, dict):
        detail = commit_error or "invalid response"
        return "UNKNOWN", f"GitHub source commit could not be authenticated: {detail}"
    if str(commit.get("sha") or "").lower() != revision:
        return "INVALID", "GitHub source commit response does not match the claim"

    run_id = claim["workflow_run_id"]
    run, _, run_error = request_json(
        f"{GITHUB_API}/repos/{encoded_repository}/actions/runs/{run_id}",
        headers=headers,
        timeout=20,
        retries=1,
    )
    if run_error or not isinstance(run, dict):
        detail = run_error or "invalid response"
        return "UNKNOWN", f"GitHub workflow run could not be authenticated: {detail}"
    if run.get("id") != run_id:
        return "INVALID", "GitHub workflow run ID does not match the claim"
    if str(run.get("head_sha") or "").lower() != revision:
        return "INVALID", "GitHub workflow run head does not match the source commit"
    run_repository = _first_value(
        run,
        ("repository", "full_name"),
        ("head_repository", "full_name"),
    )
    if (
        run_repository
        and str(run_repository).casefold() != str(repository).casefold()
    ):
        return "INVALID", "GitHub workflow run repository does not match the claim"
    if run.get("status") != "completed":
        return "UNKNOWN", "GitHub workflow run is not terminal"
    if run.get("conclusion") != "success":
        return "INVALID", "GitHub workflow run did not conclude successfully"
    workflow_identity = " ".join(
        str(run.get(key) or "")
        for key in ("name", "path", "display_title", "head_branch")
    ).casefold()
    if not any(marker in workflow_identity for marker in DEPLOYMENT_WORKFLOW_MARKERS):
        jobs_payload, _, jobs_error = request_json(
            f"{GITHUB_API}/repos/{encoded_repository}/actions/runs/{run_id}/jobs",
            headers=headers,
            timeout=20,
            retries=1,
        )
        if jobs_error or not isinstance(jobs_payload, dict):
            return (
                "UNKNOWN",
                "GitHub workflow run could not be bound to a Hugging Face deployment",
            )
        job_identity = " ".join(
            str(job.get("name") or "")
            for job in (jobs_payload.get("jobs") or [])
            if isinstance(job, dict)
        ).casefold()
        if not any(
            marker in f"{workflow_identity} {job_identity}"
            for marker in DEPLOYMENT_WORKFLOW_MARKERS
        ):
            return (
                "INVALID",
                "GitHub workflow run is not a Hugging Face deployment workflow",
            )
    return "OBSERVED", None


def _resolve_space_source_binding(
    item: dict[str, Any],
    root_url: str,
) -> dict[str, Any]:
    repo_id = str(item.get("id") or "unknown")
    runtime = item.get("runtime") if isinstance(item.get("runtime"), dict) else {}
    repo_revision = str(item.get("sha") or "").lower()
    runtime_revision = str(
        runtime.get("sha")
        or runtime.get("revision")
        or runtime.get("hf_revision")
        or ""
    ).lower()

    documents: list[tuple[dict[str, Any] | None, str, str | None]] = []
    build_document = _read_source_document(
        urllib.parse.urljoin(root_url, "api/build-info"),
        evidence="api/build-info",
        schema_mode="build",
    )
    documents.append(build_document)
    build_info_error = build_document[2] if build_document[1] != "VALID" else None
    build_info_http = (
        200
        if build_document[1] in {"VALID", "INVALID"}
        else _http_status(build_info_error)
    )

    documents.append(
        _read_source_document(
            urllib.parse.urljoin(root_url, ".well-known/szl-source.json"),
            evidence=".well-known/szl-source.json",
            schema_mode="source",
        )
    )

    repo_paths = siblings(item)
    manifest_paths = [
        path
        for path in DEPLOYMENT_MANIFEST_PATHS
        if item.get("siblings") is None or path in repo_paths
    ]
    if SHA40.fullmatch(repo_revision):
        for path in manifest_paths:
            manifest_url = (
                f"{HF}/spaces/{urllib.parse.quote(repo_id, safe='/')}/resolve/"
                f"{repo_revision}/{urllib.parse.quote(path, safe='/')}"
            )
            documents.append(
                _read_source_document(
                    manifest_url,
                    evidence=path,
                    schema_mode="manifest",
                    headers=hf_headers(),
                )
            )

    claims = [
        document
        for document, state, _ in documents
        if state == "VALID" and document
    ]
    invalid_errors = [
        error for _, state, error in documents if state == "INVALID" and error
    ]
    unknown_errors = [
        error for _, state, error in documents if state == "UNKNOWN" and error
    ]
    evidence = [str(claim["evidence"]) for claim in claims]

    if invalid_errors:
        return _binding_result(
            "INVALID",
            error="; ".join(invalid_errors),
            evidence=evidence,
            build_info_http=build_info_http,
            build_info_error=build_info_error,
        )
    if not claims:
        state = "UNKNOWN" if unknown_errors else "UNAVAILABLE"
        return _binding_result(
            state,
            error=(
                "; ".join(unknown_errors)
                if unknown_errors
                else "no source evidence observed"
            ),
            evidence=evidence,
            build_info_http=build_info_http,
            build_info_error=build_info_error,
        )

    claim = claims[0]
    for key in (
        "repository",
        "source_revision",
        "workflow_run_id",
        "hf_revision",
        "artifact_sha256",
    ):
        if any(other[key] != claim[key] for other in claims[1:]):
            return _binding_result(
                "INVALID",
                error=f"source evidence disagrees on {key}",
                evidence=evidence,
                build_info_http=build_info_http,
                build_info_error=build_info_error,
            )

    if not SHA40.fullmatch(repo_revision):
        return _binding_result(
            "UNKNOWN",
            error="immutable Hugging Face repository revision is unavailable",
            claim=claim,
            evidence=evidence,
            build_info_http=build_info_http,
            build_info_error=build_info_error,
        )
    if not runtime_revision:
        return _binding_result(
            "UNKNOWN",
            error="runtime Hugging Face revision is unavailable",
            claim=claim,
            evidence=evidence,
            build_info_http=build_info_http,
            build_info_error=build_info_error,
        )
    if not SHA40.fullmatch(runtime_revision):
        return _binding_result(
            "INVALID",
            error="runtime Hugging Face revision is malformed",
            claim=claim,
            evidence=evidence,
            build_info_http=build_info_http,
            build_info_error=build_info_error,
        )
    if repo_revision != runtime_revision or claim["hf_revision"] != repo_revision:
        return _binding_result(
            "INVALID",
            error="claimed, repository, and runtime Hugging Face revisions do not match",
            claim=claim,
            evidence=evidence,
            build_info_http=build_info_http,
            build_info_error=build_info_error,
        )
    for other in claims:
        claimed_repo = str(other.get("hf_repository") or "").strip()
        if not claimed_repo or claimed_repo.casefold() != repo_id.casefold():
            return _binding_result(
                "INVALID",
                error="claimed Hugging Face repository does not match the observed Space",
                claim=claim,
                evidence=evidence,
                build_info_http=build_info_http,
                build_info_error=build_info_error,
            )
    if unknown_errors:
        return _binding_result(
            "UNKNOWN",
            error="; ".join(unknown_errors),
            claim=claim,
            evidence=evidence,
            build_info_http=build_info_http,
            build_info_error=build_info_error,
        )

    github_state, github_error = _authenticate_github_claim(claim)
    return _binding_result(
        github_state,
        error=github_error,
        claim=claim,
        evidence=evidence,
        build_info_http=build_info_http,
        build_info_error=build_info_error,
    )

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
    source_binding = (
        _resolve_space_source_binding(item, root_url)
        if dynamic and root_url
        else _binding_result(
            "UNAVAILABLE" if dynamic else "NOT_APPLICABLE",
            error="runtime URL unavailable" if dynamic else None,
        )
    )
    source_revision = source_binding.get("source_revision")
    source_binding_state = source_binding["source_binding_state"]
    stage = runtime.get("stage") or "unknown"
    reachable = 200 <= int(root_probe.get("http") or 0) < 400
    if stage != "RUNNING" or not reachable:
        operational_state = "DEGRADED"
    elif not dynamic:
        operational_state = "STATIC_REACHABLE"
    elif healthz == 200 and source_binding_state == "OBSERVED":
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
        "build_info_http": source_binding.get("build_info_http"),
        "build_info_error": source_binding.get("build_info_error"),
        "source_binding_error": source_binding.get("source_binding_error"),
        "source_evidence": source_binding.get("source_evidence"),
        "source_repository": source_binding.get("source_repository"),
        "source_revision": source_revision,
        "source_workflow_run_id": source_binding.get("source_workflow_run_id"),
        "source_hf_revision": source_binding.get("source_hf_revision"),
        "source_artifact_sha256": source_binding.get("source_artifact_sha256"),
        "source_binding_state": source_binding_state,
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
    has_items = items is not None
    has_error = error is not None
    return {
        "ok": has_items and not has_error,
        "partial": has_items and has_error,
        "count": len(items) if has_items else None,
        "error": error,
        "items": items if has_items else [],
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
    with cf.ThreadPoolExecutor(max_workers=7) as executor:
        authentication_future = executor.submit(collect_hf_authentication)
        futures = {
            name: executor.submit(hf_paginate, path) for name, path in paths.items()
        }
        raw = {name: future.result() for name, future in futures.items()}
        authentication = authentication_future.result()

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
        buckets_error = f"direct bucket listing unavailable ({buckets_error}); collection-only scope"

    assets = {
        "models": asset_result(models, models_error),
        "datasets": asset_result(datasets, datasets_error),
        "spaces": asset_result(spaces, spaces_error),
        "kernels": asset_result(kernels, kernels_error),
        "collections": asset_result(collections, collections_error),
        "buckets": asset_result(buckets, buckets_error),
    }
    authentication = finalize_hf_authentication(authentication, assets)

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
        "authentication": authentication,
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
                sum(
                    1 for space in spaces or [] if space.get("card_state") == "COMPLETE"
                )
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
                sum(
                    1 for model in models or [] if model.get("estimator_files_observed")
                )
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
