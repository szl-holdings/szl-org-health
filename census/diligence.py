"""Deterministic, fail-closed Series-A diligence compiler.

The compiler consumes one already-collected schema-v2 census.  It performs no
network calls and does not promote policy targets, transport reachability, or
input-supplied aggregate labels into observed truth.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import math
import re
import subprocess
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any


ARTIFACT_SCHEMA = "szl.series-a-diligence/v1"
POLICY_SCHEMA = "szl.series-a-diligence-policy/v1"
CLAIM_BOUNDARY = (
    "This artifact reports only the supplied census, optional public receipt, and versioned target policy; "
    "it is not a certification, deployment receipt, or investor claim of production readiness."
)
REPORT_SCHEMA_VERSION = 2
MAX_REPORT_AGE_SECONDS = 24 * 60 * 60
MAX_FUTURE_SKEW_SECONDS = 5 * 60
MAX_JSON_BYTES = 32 * 1024 * 1024
MAX_RECEIPT_BYTES = 1024 * 1024
MAX_WALK_DEPTH = 80
SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA64 = re.compile(r"^[0-9a-f]{64}$")
COLLECTION_ID = re.compile(r"^[0-9a-f]{32}$")
RFC3339 = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
    r"(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$"
)
DATE_ONLY = re.compile(r"^\d{4}-\d{2}-\d{2}$")
SOURCE_NAME = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
REPO_BACKED_ASSET_KINDS = {"models", "datasets", "spaces", "kernels"}
SENSITIVE_TEXT = (
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(
        r"\b(?:gh[pousr]_[A-Za-z0-9_]{8,}|github_pat_[A-Za-z0-9_]{8,}|"
        r"hf_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{8,})\b"
    ),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"(?i)(?:access_token|api_key|password)=[^&\s]{4,}"),
)
POLICY_UNAVAILABLE_REASON = "Series-A diligence policy is unavailable."
POLICY_DIVERGENT_REASON = (
    "Series-A diligence policy is invalid or differs from the locked policy."
)
POLICY_MEASURED_REASON = "Versioned Series-A target policy was loaded."
PUBLIC_RECEIPT_UNAVAILABLE_REASON = (
    "No public census receipt was supplied; exact public bytes are not receipt-bound."
)
PUBLIC_RECEIPT_DIVERGENT_REASON = "The supplied public census and receipt do not satisfy the exact-byte collection binding."
PUBLIC_RECEIPT_MEASURED_REASON = (
    "Exact supplied public census bytes match a FRESH_COLLECTION_BOUND receipt projection; "
    "internal snapshot bytes and run identity are not independently verified."
)
HF_ID = re.compile(r"^SZLHOLDINGS/[A-Za-z0-9._-]+$")
GITHUB_REPOSITORY = re.compile(r"^[A-Za-z0-9._-]+$")
TRUTH_STATES = {"MEASURED", "BLOCKED", "UNAVAILABLE", "DIVERGENT", "STALE"}
CONTROL_STATUSES = {"PASS", "FAIL", "UNKNOWN", "NOT_APPLICABLE"}
CI_STATES = {"success", "failure", "pending", "unknown", "archived"}
REPOSITORY_CLASSIFICATIONS = {
    "archive",
    "control-plane",
    "production",
    "product-surface",
    "research",
    "unclassified",
}
SENSITIVE_KEYS = {
    "access_token",
    "api_key",
    "apikey",
    "authorization",
    "client_secret",
    "cookie",
    "password",
    "private_key",
    "refresh_token",
    "token",
}
REQUIRED_ASSET_KINDS = (
    "models",
    "datasets",
    "spaces",
    "kernels",
    "collections",
    "buckets",
)
REQUIRED_REQUIREMENTS = {
    "census_schema",
    "compiler_source",
    "correction_and_overclaim_ledger",
    "generated_api_contract",
    "governed_agent_bench",
    "governed_mcp",
    "github_inventory",
    "github_release_gate",
    "hf_inventory",
    "hf_release_gate",
    "model_promotion",
    "product_proof_roles",
    "public_space_policy",
    "public_snapshot_receipt",
    "route_tab_inventory",
    "shared_design_system_contract",
    "snapshot_freshness",
    "space_cost_posture",
    "space_deployment_reconciliation",
    "target_policy",
}
LOCKED_DOMAIN_ROLES = (
    (
        "a-11-oy.com",
        "PRODUCT",
        "SZL Four-Clone Recommended Upgrade Payload issued 2026-07-25",
    ),
    (
        "a11oy.net",
        "PROOF",
        "SZL Four-Clone Recommended Upgrade Payload issued 2026-07-25",
    ),
)
LOCKED_KILLINCHU_EXCEPTION = {
    "surface": "SZLHOLDINGS/killinchu",
    "decision": "ACCEPTED_CONDITIONAL",
    "decision_date": "2026-07-25",
    "review_due": "2026-10-23",
    "source_repository": "szl-holdings/a11oy",
    "source_path": "docs/decisions/2026-07-25-killinchu-public-space-exception.md",
    "source_blob_oid": "02fe8afa7a6063d3f6265882fa0b0dadace1e6c7",
}
LOCKED_POLICY = {
    "schema": POLICY_SCHEMA,
    "status": "TARGET",
    "domain_roles": [
        {"domain": domain, "role": role, "source": source}
        for domain, role, source in LOCKED_DOMAIN_ROLES
    ],
    "public_space_policy": {
        "normal_limit": 5,
        "normal_allowlist_state": "UNAVAILABLE",
        "exceptions": [LOCKED_KILLINCHU_EXCEPTION],
    },
}
PRODUCT_PROOF_REASON = (
    "The census observes site transport, not route ownership or role conformance."
)
GOVERNED_MCP_REASON = "The census does not verify governed MCP authorization, receipts, or endpoint availability."
MODEL_PROMOTION_REASON = (
    "Immutable revisions and licenses are inventoried, but SZL eval reproduction "
    "and production promotion are not observed."
)
ROUTE_TABS_REASON = (
    "No current route/tab purpose, data-source, and owner collector exists."
)
COST_POSTURE_REASON = (
    "The census does not observe billed cost, sleep policy, or capacity quotas."
)
FIXED_UNAVAILABLE_REQUIREMENTS = {
    "generated_api_contract": (
        "A generated API contract has not been collected and verified."
    ),
    "shared_design_system_contract": (
        "A shared design-system contract has not been collected and verified."
    ),
    "space_deployment_reconciliation": (
        "The full GitHub SHA, Hub SHA, image digest, registered organs, and "
        "observed routes chain is unavailable until collected."
    ),
}
GOVERNANCE_CONTROL_SEVERITIES = {
    "GH-INVENTORY": "HIGH",
    "GH-ACTIVE-CI": "HIGH",
    "GH-BRANCH-PROTECTION": "CRITICAL",
    "GH-HIGH-CODE-ALERTS": "CRITICAL",
    "GH-SECRET-ALERTS": "CRITICAL",
    "GH-DEPENDABOT-ALERTS": "HIGH",
    "GH-REPOSITORY-CLASSIFICATION": "HIGH",
    "HF-INVENTORY": "HIGH",
    "HF-CARDS": "HIGH",
    "HF-LICENSES": "HIGH",
    "HF-SAFE-MODEL-FORMATS": "CRITICAL",
    "HF-IMMUTABLE-REVISIONS": "CRITICAL",
    "HF-DYNAMIC-SPACE-SOURCE-BINDING": "CRITICAL",
    "DNS-SPF": "HIGH",
    "DNS-DMARC-REJECT": "HIGH",
}
SUMMARY_KEYS = {
    "github_repositories",
    "github_active_repositories",
    "github_ci_failures",
    "hf_models",
    "hf_datasets",
    "hf_spaces",
    "hf_public_spaces",
    "open_corrections",
    "open_overclaims",
}
ARTIFACT_KEYS = {
    "schema",
    "state",
    "claim_boundary",
    "assessed_at",
    "source_binding",
    "public_snapshot_binding",
    "sources",
    "requirements",
    "inventory",
    "product_proof_roles",
    "public_space_policy",
    "governed_agent_bench",
    "governed_mcp",
    "model_promotion",
    "route_tab_inventory",
    "space_cost_posture",
    "governance_evidence",
    "correction_ledger",
    "overclaim_ledger",
    "summary",
    "gaps",
    "digest_sha256",
}
SOURCE_BOUND_PATHS = (
    ".gitattributes",
    "build_series_a_diligence.py",
    "census/__init__.py",
    "census/diligence.py",
    "diligence/policy.json",
    "schemas/series-a-diligence.schema.json",
)
PUBLIC_HF_COMMON_ITEM_FIELDS = {
    "private",
    "url",
    "sha",
    "last_modified",
    "card_state",
    "card_present",
    "license_declared",
    "managed_marker_present",
    "provenance_marker_present",
    "likes",
    "downloads_30d",
    "file_count_observed",
}
PUBLIC_HF_KIND_ITEM_FIELDS = {
    "models": {
        "pipeline_tag",
        "contract",
        "weight_state",
        "artifact_state",
        "payload_manifest_state",
        "payload_manifest_aggregate_verified",
        "payload_manifest_declared_files",
        "payload_manifest_verified_files",
        "weight_files_observed",
        "estimator_files_observed",
        "embedding_files_observed",
        "model_artifact_files_observed",
        "payload_manifest_missing_files",
        "payload_manifest_mismatched_files",
    },
    "datasets": set(),
    "spaces": {
        "sdk",
        "stage",
        "subdomain",
        "source_revision",
        "source_binding_state",
        "operational_state",
        "healthz_contract",
        "http",
        "healthz",
        "hardware",
        "build_info_http",
    },
    "kernels": {
        "metadata_state",
        "tree_state",
        "contract_state",
        "selfcheck_state",
        "build_variants_present",
    },
    "collections": {"title", "owner", "last_updated", "complete", "upvotes"},
    "buckets": {
        "created_at",
        "updated_at",
        "tree_state",
        "documentation_state",
        "readme_present",
        "size_bytes",
        "total_files",
    },
}


class DiligenceError(ValueError):
    """The supplied evidence cannot be interpreted without guessing."""


def _reject_constant(value: str) -> None:
    raise DiligenceError(f"non-standard JSON constant is forbidden: {value}")


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DiligenceError("duplicate JSON member is forbidden")
        result[key] = value
    return result


def _walk(value: Any, *, path: str = "$", depth: int = 0) -> None:
    if depth > MAX_WALK_DEPTH:
        raise DiligenceError(f"evidence nesting exceeds {MAX_WALK_DEPTH}")
    if isinstance(value, float) and not math.isfinite(value):
        raise DiligenceError("non-finite number is forbidden")
    if isinstance(value, Mapping):
        for key, child in value.items():
            if not isinstance(key, str):
                raise DiligenceError("non-string object key is forbidden")
            normalized = key.lower().replace("-", "_")
            if normalized in SENSITIVE_KEYS:
                raise DiligenceError("sensitive field is forbidden")
            _walk(child, path=f"{path}.{key}", depth=depth + 1)
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, child in enumerate(value):
            _walk(child, path=f"{path}[{index}]", depth=depth + 1)


def _sensitive_text_paths(value: Any, *, path: str = "$") -> list[str]:
    found: list[str] = []
    if isinstance(value, Mapping):
        for key, child in value.items():
            found.extend(_sensitive_text_paths(child, path=f"{path}.{key}"))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            found.extend(_sensitive_text_paths(child, path=f"{path}[{index}]"))
    elif isinstance(value, str) and any(
        pattern.search(value) is not None for pattern in SENSITIVE_TEXT
    ):
        found.append(path)
    return found


def strict_parse_json_bytes(
    payload: bytes, *, source: str, max_bytes: int = MAX_JSON_BYTES
) -> dict[str, Any]:
    """Parse the exact bounded UTF-8 bytes used for a public digest."""

    if not isinstance(payload, bytes) or len(payload) > max_bytes:
        raise DiligenceError(f"JSON input exceeds {max_bytes} bytes")
    try:
        text = payload.decode("utf-8")
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise DiligenceError("JSON input is unavailable or invalid") from None
    if not isinstance(value, dict):
        raise DiligenceError("JSON root must be an object")
    _walk(value)
    return value


def strict_read_json(
    path: str | Path, *, max_bytes: int = MAX_JSON_BYTES
) -> tuple[dict[str, Any], bytes]:
    """Read once, with a hard byte cap, so parsing and hashing share bytes."""

    source = Path(path)
    try:
        with source.open("rb") as stream:
            payload = stream.read(max_bytes + 1)
    except OSError:
        raise DiligenceError("JSON input is unavailable") from None
    return strict_parse_json_bytes(
        payload, source=str(source), max_bytes=max_bytes
    ), payload


def strict_load_json(path: str | Path) -> dict[str, Any]:
    """Load a bounded strict JSON object, rejecting parser ambiguity."""

    value, _payload = strict_read_json(path)
    return value


def _has_private_inventory(report: Mapping[str, Any]) -> bool:
    """Detect source markers that must never enter an investor artifact."""

    sources = report.get("sources")
    if not isinstance(sources, Mapping):
        return False
    github = sources.get("github")
    if isinstance(github, Mapping):
        data = github.get("data")
        repositories = data.get("repos") if isinstance(data, Mapping) else None
        if isinstance(repositories, Mapping):
            for repository in repositories.values():
                if isinstance(repository, Mapping) and (
                    (
                        "visibility" in repository
                        and repository["visibility"] != "public"
                    )
                    or ("private" in repository and repository["private"] is not False)
                    or ("public" in repository and repository["public"] is not True)
                ):
                    return True
    huggingface = sources.get("huggingface")
    if isinstance(huggingface, Mapping):
        data = huggingface.get("data")
        assets = data.get("assets") if isinstance(data, Mapping) else None
        if isinstance(assets, Mapping):
            for group in assets.values():
                items = group.get("items") if isinstance(group, Mapping) else None
                if isinstance(items, list) and any(
                    isinstance(item, Mapping)
                    and "private" in item
                    and item["private"] is not False
                    for item in items
                ):
                    return True
    return False


def require_public_projection_input(report: Mapping[str, Any]) -> None:
    """Reject non-public inputs before the CLI publishes diligence outputs.

    This is a structural privacy boundary, not proof that a provider really
    serves the claimed assets publicly. The receipt check remains separate.
    Diagnostics are fixed so malformed input cannot be echoed into CI logs.
    """

    error = "supplied census is not a closed public projection"
    try:
        required_root = {
            "schema_version",
            "projection_schema",
            "source_snapshot_sha256",
            "generated_at",
            "exposure",
            "sources",
            "governance",
        }
        if (
            not isinstance(report, Mapping)
            or set(report) not in (required_root, required_root | {"collection"})
            or report.get("schema_version") != REPORT_SCHEMA_VERSION
            or report.get("projection_schema") != "szl.estate-public-projection/v1"
            or report.get("exposure") != "public"
            or not _valid_sha256(report.get("source_snapshot_sha256"))
            or _has_private_inventory(report)
        ):
            raise DiligenceError(error)

        collection = report.get("collection")
        if collection is not None and (
            not isinstance(collection, Mapping)
            or set(collection) != {"schema", "id", "started_at", "completed_at"}
            or collection.get("schema") != "szl.census-collection/v1"
            or not isinstance(collection.get("id"), str)
            or COLLECTION_ID.fullmatch(collection["id"]) is None
        ):
            raise DiligenceError(error)

        sources = report.get("sources")
        if not isinstance(sources, Mapping) or set(sources) != {
            "github",
            "huggingface",
            "sites",
            "dns",
        }:
            raise DiligenceError(error)
        for source in sources.values():
            if (
                not isinstance(source, Mapping)
                or set(source) != {"ok", "diagnostic_state", "error", "data"}
                or not isinstance(source.get("data"), Mapping)
            ):
                raise DiligenceError(error)

        github = sources["github"]["data"]
        if set(github) != {
            "discovery",
            "summary",
            "repos",
            "alerts",
            "open_prs",
            "open_issues",
        }:
            raise DiligenceError(error)
        discovery = github.get("discovery")
        alerts = github.get("alerts")
        if (
            not isinstance(discovery, Mapping)
            or discovery.get("complete") is not False
            or discovery.get("scope") != "public-projection"
            or not isinstance(alerts, Mapping)
            or alerts.get("complete") is not False
            or github.get("open_prs") is not None
            or github.get("open_issues") is not None
        ):
            raise DiligenceError(error)
        repositories = github.get("repos")
        if not isinstance(repositories, Mapping):
            raise DiligenceError(error)
        for name, repository in repositories.items():
            if (
                not isinstance(name, str)
                or GITHUB_REPOSITORY.fullmatch(name) is None
                or not isinstance(repository, Mapping)
                or set(repository)
                != {
                    "visibility",
                    "archived",
                    "fork",
                    "ci",
                    "protected",
                    "classification",
                    "url",
                }
                or repository.get("visibility") != "public"
                or repository.get("url") != f"https://github.com/szl-holdings/{name}"
            ):
                raise DiligenceError(error)

        huggingface = sources["huggingface"]["data"]
        if set(huggingface) != {"organization", "authentication", "summary", "assets"}:
            raise DiligenceError(error)
        authentication = huggingface.get("authentication")
        if (
            huggingface.get("organization") != "SZLHOLDINGS"
            or not isinstance(authentication, Mapping)
            or dict(authentication)
            != {
                "evidence_scope": "PUBLIC_PROJECTION",
                "organization_complete": False,
            }
        ):
            raise DiligenceError(error)
        assets = huggingface.get("assets")
        if not isinstance(assets, Mapping) or set(assets) != set(REQUIRED_ASSET_KINDS):
            raise DiligenceError(error)
        for kind, group in assets.items():
            if (
                not isinstance(group, Mapping)
                or set(group) != {"ok", "count", "diagnostic_state", "error", "items"}
                or not isinstance(group.get("items"), list)
            ):
                raise DiligenceError(error)
            identifier_field = "slug" if kind == "collections" else "id"
            route = "" if kind == "models" else f"{kind}/"
            for item in group["items"]:
                if (
                    not isinstance(item, Mapping)
                    or item.get("private") is not False
                    or not set(item)
                    <= (
                        PUBLIC_HF_COMMON_ITEM_FIELDS
                        | PUBLIC_HF_KIND_ITEM_FIELDS[kind]
                        | {identifier_field}
                    )
                    or not isinstance(item.get(identifier_field), str)
                    or HF_ID.fullmatch(item[identifier_field]) is None
                    or item.get("url")
                    != f"https://huggingface.co/{route}{item[identifier_field]}"
                ):
                    raise DiligenceError(error)
    except (KeyError, TypeError, ValueError, RecursionError):
        raise DiligenceError(error) from None


def _binding_view(value: Any, *, path: tuple[str, ...] = ()) -> Any:
    """Normalize only census collections that are explicitly unordered.

    JSON arrays are ordered by default.  The census contract declares asset
    inventories and governance controls to be sets, so only those arrays are
    sorted for source binding.  Arbitrary arrays retain their order and cannot
    collide with a reversed evidence sequence.
    """

    if isinstance(value, Mapping):
        return {
            str(key): _binding_view(child, path=(*path, str(key)))
            for key, child in sorted(value.items())
        }
    if isinstance(value, list):
        children = [_binding_view(child, path=(*path, "[]")) for child in value]
        is_controls = path == ("governance", "controls")
        is_asset_items = (
            len(path) == 6
            and path[:4] == ("sources", "huggingface", "data", "assets")
            and path[4] in REQUIRED_ASSET_KINDS
            and path[5] == "items"
        )
        if is_controls or is_asset_items:
            return sorted(
                children,
                key=lambda child: json.dumps(
                    child,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                    allow_nan=False,
                ),
            )
        return children
    return value


def canonical_bytes(value: Any) -> bytes:
    _walk(value)
    try:
        rendered = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError, RecursionError) as exc:
        raise DiligenceError(f"value is not canonical JSON: {exc}") from exc
    return rendered.encode("utf-8")


def semantic_sha256(value: Any) -> str:
    """Hash canonical JSON while preserving array order.

    Mapping key order is not semantic in JSON, but array order is.  Keeping
    arrays intact prevents two byte-distinct ordered evidence sets from sharing
    a source-binding digest.
    """

    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _parse_timestamp(value: Any) -> dt.datetime | None:
    if not isinstance(value, str) or RFC3339.fullmatch(value) is None:
        return None
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = dt.datetime.fromisoformat(normalized)
        if parsed.tzinfo is None:
            return None
        return parsed.astimezone(dt.UTC)
    except (ValueError, OverflowError):
        return None


def _parse_policy_date(value: Any) -> dt.date | None:
    if not isinstance(value, str) or DATE_ONLY.fullmatch(value) is None:
        return None
    try:
        return dt.date.fromisoformat(value)
    except ValueError:
        return None


def _valid_exception_chronology(exception: Mapping[str, Any]) -> bool:
    decision_date = _parse_policy_date(exception.get("decision_date"))
    review_due = _parse_policy_date(exception.get("review_due"))
    return (
        decision_date is not None
        and review_due is not None
        and decision_date <= review_due
    )


def _timestamp(value: dt.datetime) -> str:
    return (
        value.astimezone(dt.UTC)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _as_of(value: str | dt.datetime | None) -> dt.datetime:
    if value is None:
        return dt.datetime.now(dt.UTC).replace(microsecond=0)
    if isinstance(value, dt.datetime):
        if value.tzinfo is None:
            raise DiligenceError("as-of timestamp must include a timezone")
        return value.astimezone(dt.UTC).replace(microsecond=0)
    parsed = _parse_timestamp(value)
    if parsed is None:
        raise DiligenceError("as-of timestamp must be RFC3339 with a timezone")
    return parsed.replace(microsecond=0)


def _nonnegative_int(value: Any) -> int | None:
    return value if type(value) is int and value >= 0 else None


def _state_for_revision(
    value: Any,
    *,
    verified: bool,
) -> tuple[str, str | None, str]:
    if value is None or value == "":
        return (
            "UNAVAILABLE",
            None,
            "An exact compiler source revision was not supplied.",
        )
    if not isinstance(value, str) or not SHA40.fullmatch(value) or value == "0" * 40:
        return (
            "DIVERGENT",
            None,
            "Compiler source revision is not a non-null lowercase Git SHA.",
        )
    if verified is not True:
        return (
            "UNAVAILABLE",
            value,
            "Compiler source revision was supplied but not verified against a clean checkout.",
        )
    return "MEASURED", value, "Compiler source is bound to an exact Git revision."


def _verify_compiler_source_revision(
    value: Any,
    *,
    root: Path | None = None,
) -> bool:
    """Verify the executing regular-file bytes against one exact HEAD tree."""

    if (
        not isinstance(value, str)
        or SHA40.fullmatch(value) is None
        or value == "0" * 40
    ):
        return False
    repository = (root or Path(__file__).resolve().parents[1]).resolve()

    def run(*arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", "-C", str(repository), *arguments],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )

    try:
        top = run("rev-parse", "--show-toplevel")
        if top.returncode != 0 or Path(top.stdout.strip()).resolve() != repository:
            return False
        head = run("rev-parse", "HEAD")
        if head.returncode != 0 or head.stdout.strip() != value:
            return False
        for relative in SOURCE_BOUND_PATHS:
            working = repository / relative
            if working.is_symlink() or not working.is_file():
                return False
            if working.stat().st_nlink != 1:
                return False
            tracked = run("ls-files", "-v", "--", relative)
            tracked_lines = tracked.stdout.splitlines()
            if tracked.returncode != 0 or tracked_lines != [f"H {relative}"]:
                return False
            tree = run("ls-tree", value, "--", relative)
            tree_line = tree.stdout.strip()
            if tree.returncode != 0 or "\t" not in tree_line:
                return False
            metadata, tree_path = tree_line.split("\t", 1)
            parts = metadata.split()
            if (
                tree_path != relative
                or len(parts) != 3
                or parts[0] not in {"100644", "100755"}
                or parts[1] != "blob"
                or not SHA40.fullmatch(parts[2])
            ):
                return False
            working_hash = run(
                "hash-object",
                "--no-filters",
                str(working),
            )
            if working_hash.returncode != 0 or working_hash.stdout.strip() != parts[2]:
                return False
        return True
    except (OSError, subprocess.SubprocessError, ValueError):
        return False


def _source_summary(report: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, str]]:
    raw_sources = report.get("sources")
    if not isinstance(raw_sources, Mapping):
        return {}, {"sources": "DIVERGENT"}
    summaries: dict[str, Any] = {}
    states: dict[str, str] = {}
    for name in sorted(str(key) for key in raw_sources):
        if SOURCE_NAME.fullmatch(name) is None:
            raise DiligenceError("source name is malformed")
        raw = raw_sources.get(name)
        if not isinstance(raw, Mapping) or type(raw.get("ok")) is not bool:
            state = "DIVERGENT"
            error = "Source wrapper is malformed."
        elif raw.get("ok") is False:
            state = "UNAVAILABLE"
            # Collector errors are not evidence and can contain request headers,
            # credential-bearing URLs, or provider text.  Never render them.
            error = "Source collection failed; inspect the protected collector log."
        elif not isinstance(raw.get("data"), Mapping):
            state = "DIVERGENT"
            error = "Successful source has no object-shaped data."
        else:
            state = "MEASURED"
            error = None
        summaries[name] = {"state": state, "error": error}
        states[name] = state
    return summaries, states


def _github_inventory(report: Mapping[str, Any], source_state: str) -> dict[str, Any]:
    empty = {
        "state": source_state,
        "release_gate": source_state,
        "repository_count": None,
        "active_count": None,
        "archived_count": None,
        "ci": {"success": None, "failure": None, "pending": None, "unknown": None},
        "blocked_repositories": [],
        "unprotected_repositories": [],
        "protection_unknown_repositories": [],
        "unclassified_repositories": [],
        "reason": "GitHub inventory is unavailable.",
    }
    if source_state != "MEASURED":
        return empty
    github = report["sources"]["github"]["data"]
    repos = github.get("repos")
    summary = github.get("summary")
    discovery = github.get("discovery")
    if (
        not isinstance(repos, Mapping)
        or not isinstance(summary, Mapping)
        or not isinstance(discovery, Mapping)
    ):
        return {
            **empty,
            "state": "DIVERGENT",
            "release_gate": "DIVERGENT",
            "reason": "GitHub inventory structure is malformed.",
        }

    derived = {
        "total": 0,
        "active": 0,
        "archived": 0,
        "ci_green": 0,
        "ci_red": 0,
        "ci_unknown": 0,
    }
    ci_counts = {"success": 0, "failure": 0, "pending": 0, "unknown": 0}
    blocked: list[str] = []
    unprotected: list[str] = []
    protection_unknown: list[str] = []
    unclassified: list[str] = []
    for name, raw in sorted(repos.items()):
        if (
            not isinstance(name, str)
            or GITHUB_REPOSITORY.fullmatch(name) is None
            or not isinstance(raw, Mapping)
        ):
            return {
                **empty,
                "state": "DIVERGENT",
                "release_gate": "DIVERGENT",
                "reason": "GitHub repository entry is malformed.",
            }
        archived = raw.get("archived")
        ci = raw.get("ci")
        protected = raw.get("protected")
        classification = raw.get("classification")
        if type(archived) is not bool or not isinstance(ci, str) or ci not in CI_STATES:
            return {
                **empty,
                "state": "DIVERGENT",
                "release_gate": "DIVERGENT",
                "reason": "GitHub repository evidence is malformed.",
            }
        if protected is not None and type(protected) is not bool:
            return {
                **empty,
                "state": "DIVERGENT",
                "release_gate": "DIVERGENT",
                "reason": "Branch-protection evidence is malformed.",
            }
        if (
            not isinstance(classification, str)
            or classification not in REPOSITORY_CLASSIFICATIONS
        ):
            return {
                **empty,
                "state": "DIVERGENT",
                "release_gate": "DIVERGENT",
                "reason": "Repository classification is malformed.",
            }
        if archived and classification != "archive":
            return {
                **empty,
                "state": "DIVERGENT",
                "release_gate": "DIVERGENT",
                "reason": "Archived repository classification disagrees with lifecycle state.",
            }
        if not archived and classification == "archive":
            return {
                **empty,
                "state": "DIVERGENT",
                "release_gate": "DIVERGENT",
                "reason": "Active repository is classified as an archive.",
            }
        if archived != (ci == "archived"):
            return {
                **empty,
                "state": "DIVERGENT",
                "release_gate": "DIVERGENT",
                "reason": "Repository lifecycle and CI state disagree.",
            }
        derived["total"] += 1
        if archived:
            derived["archived"] += 1
            continue
        derived["active"] += 1
        if ci in ci_counts:
            ci_counts[ci] += 1
        if ci == "success":
            derived["ci_green"] += 1
        elif ci == "failure":
            derived["ci_red"] += 1
            blocked.append(name)
        else:
            derived["ci_unknown"] += 1
            blocked.append(name)
        if protected is False:
            unprotected.append(name)
        elif protected is None:
            protection_unknown.append(name)
        if classification == "unclassified":
            unclassified.append(name)

    expected_fields = (
        "total",
        "active",
        "archived",
        "ci_green",
        "ci_red",
        "ci_unknown",
    )
    mismatches: list[str] = []
    for field in expected_fields:
        observed = _nonnegative_int(summary.get(field))
        if observed is None or observed != derived[field]:
            mismatches.append(field)
    if mismatches:
        state = "DIVERGENT"
        release_gate = "DIVERGENT"
        reason = f"GitHub summary disagrees with repository evidence: {', '.join(mismatches)}."
    elif discovery.get("complete") is not True:
        state = "UNAVAILABLE"
        release_gate = "UNAVAILABLE"
        reason = "GitHub discovery did not prove complete organization coverage."
    else:
        state = "MEASURED"
        blockers_exist = bool(
            blocked or unprotected or protection_unknown or unclassified
        )
        release_gate = "BLOCKED" if blockers_exist else "MEASURED"
        reason = "GitHub inventory was recomputed from repository evidence."
    inventory_measured = state == "MEASURED"
    return {
        "state": state,
        "release_gate": release_gate,
        "repository_count": derived["total"] if inventory_measured else None,
        "active_count": derived["active"] if inventory_measured else None,
        "archived_count": derived["archived"] if inventory_measured else None,
        "ci": (
            ci_counts
            if inventory_measured
            else {"success": None, "failure": None, "pending": None, "unknown": None}
        ),
        "blocked_repositories": sorted(blocked),
        "unprotected_repositories": sorted(unprotected),
        "protection_unknown_repositories": sorted(protection_unknown),
        "unclassified_repositories": sorted(unclassified),
        "reason": reason,
    }


def _valid_sha(value: Any) -> bool:
    return (
        isinstance(value, str)
        and SHA40.fullmatch(value) is not None
        and value != "0" * 40
    )


def _valid_http(value: Any, *, exact: int | None = None) -> bool:
    if type(value) is not int:
        return False
    return value == exact if exact is not None else 200 <= value < 300


def _valid_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and SHA64.fullmatch(value) is not None
        and value != "0" * 64
    )


def _valid_benchmark_receipt(value: Any) -> bool:
    return (
        isinstance(value, str)
        and re.fullmatch(r"[A-Za-z0-9._:/-]{1,200}", value) is not None
        and any(character.isalnum() for character in value)
        and not any(pattern.search(value) is not None for pattern in SENSITIVE_TEXT)
    )


def _benchmark_http(value: Any) -> int | None:
    return value if type(value) is int and 100 <= value <= 599 else None


def _benchmark_dataset_summary(
    item: Mapping[str, Any] | None,
    state: str,
) -> dict[str, Any] | None:
    if state != "MEASURED" or item is None:
        return None
    if (
        item.get("id") != "SZLHOLDINGS/governed-agent-bench"
        or not _valid_sha(item.get("sha"))
        or type(item.get("private")) is not bool
    ):
        return None
    card_state = item.get("card_state")
    if card_state not in ("COMPLETE", "INCOMPLETE", "UNKNOWN"):
        card_state = "UNKNOWN"
    return {
        "id": item["id"],
        "sha": item["sha"],
        "private": item["private"],
        "license_declared": item.get("license_declared") is True,
        "card_state": card_state,
    }


def _benchmark_space_summary(
    item: Mapping[str, Any] | None,
    state: str,
) -> dict[str, Any] | None:
    if state != "MEASURED" or item is None:
        return None
    if (
        item.get("id") != "SZLHOLDINGS/governed-agent-bench"
        or not _valid_sha(item.get("sha"))
        or type(item.get("private")) is not bool
    ):
        return None
    stage = item.get("stage")
    if (
        not isinstance(stage, str)
        or re.fullmatch(r"(?:[A-Z][A-Z0-9_]{0,63}|unknown)", stage) is None
    ):
        stage = "unknown"
    source_binding_state = item.get("source_binding_state")
    if source_binding_state not in (
        None,
        "OBSERVED",
        "UNAVAILABLE",
        "NOT_APPLICABLE",
    ):
        source_binding_state = None
    operational_state = item.get("operational_state")
    if operational_state not in (
        None,
        "DEGRADED",
        "STATIC_REACHABLE",
        "OPERATIONAL_SOURCE_BOUND",
        "RUNTIME_HEALTHY_UNBOUND",
        "REACHABLE_UNVERIFIED",
    ):
        operational_state = None
    reproduction_state = item.get("eval_reproduction_state")
    if reproduction_state != "VERIFIED":
        reproduction_state = None
    return {
        "id": item["id"],
        "sha": item["sha"],
        "private": item["private"],
        "stage": stage,
        "source_revision": (
            item.get("source_revision")
            if _valid_sha(item.get("source_revision"))
            else None
        ),
        "canonical_source_revision": (
            item.get("canonical_source_revision")
            if _valid_sha(item.get("canonical_source_revision"))
            else None
        ),
        "source_binding_state": source_binding_state,
        "operational_state": operational_state,
        "http": _benchmark_http(item.get("http")),
        "healthz": _benchmark_http(item.get("healthz")),
        "healthz_contract": (
            item.get("healthz_contract")
            if type(item.get("healthz_contract")) is bool
            else None
        ),
        "build_info_http": _benchmark_http(item.get("build_info_http")),
        "leaderboard_http": _benchmark_http(item.get("leaderboard_http")),
        "eval_dataset_revision": (
            item.get("eval_dataset_revision")
            if _valid_sha(item.get("eval_dataset_revision"))
            else None
        ),
        "eval_space_revision": (
            item.get("eval_space_revision")
            if _valid_sha(item.get("eval_space_revision"))
            else None
        ),
        "eval_output_revision": (
            item.get("eval_output_revision")
            if _valid_sha(item.get("eval_output_revision"))
            else None
        ),
        "eval_output_sha256": (
            item.get("eval_output_sha256")
            if _valid_sha256(item.get("eval_output_sha256"))
            else None
        ),
        "eval_receipt_id": (
            item.get("eval_receipt_id")
            if _valid_benchmark_receipt(item.get("eval_receipt_id"))
            else None
        ),
        "eval_reproduction_state": reproduction_state,
    }


def _dynamic_space_bound(item: Mapping[str, Any]) -> bool:
    """Require primitive runtime evidence, never caller-supplied summary labels alone."""

    source = item.get("source_revision")
    canonical = item.get("canonical_source_revision")
    return bool(
        item.get("stage") == "RUNNING"
        and _valid_sha(item.get("sha"))
        and _valid_sha(source)
        and _valid_sha(canonical)
        and source == canonical
        and item.get("source_binding_state") == "OBSERVED"
        and item.get("operational_state") == "OPERATIONAL_SOURCE_BOUND"
        and _valid_http(item.get("http"))
        and _valid_http(item.get("healthz"), exact=200)
        and item.get("healthz_contract") is True
        and _valid_http(item.get("build_info_http"), exact=200)
    )


def _hf_inventory(
    report: Mapping[str, Any],
    source_state: str,
) -> tuple[
    dict[str, Any],
    dict[str, list[dict[str, Any]]],
    dict[str, str],
]:
    empty = {
        "state": source_state,
        "release_gate": source_state,
        "counts": {kind: None for kind in REQUIRED_ASSET_KINDS},
        "subinventory_states": {kind: source_state for kind in REQUIRED_ASSET_KINDS},
        "public_space_count": None,
        "public_space_ids": [],
        "invalid_asset_ids": [],
        "duplicate_asset_ids": [],
        "invalid_revision_ids": [],
        "missing_license_ids": [],
        "visibility_unknown_ids": [],
        "running_unbound_spaces": [],
        "non_running_dynamic_spaces": [],
        "reason": "Hugging Face inventory is unavailable.",
    }
    blank_items = {kind: [] for kind in REQUIRED_ASSET_KINDS}
    blank_states = {kind: source_state for kind in REQUIRED_ASSET_KINDS}
    if source_state != "MEASURED":
        return empty, blank_items, blank_states
    huggingface = report["sources"]["huggingface"]["data"]
    assets = huggingface.get("assets")
    if not isinstance(assets, Mapping):
        divergent_states = {kind: "DIVERGENT" for kind in REQUIRED_ASSET_KINDS}
        return (
            {
                **empty,
                "state": "DIVERGENT",
                "release_gate": "DIVERGENT",
                "subinventory_states": divergent_states,
                "reason": "Hugging Face asset inventory is malformed.",
            },
            blank_items,
            divergent_states,
        )

    authentication = huggingface.get("authentication")
    public_projection = (
        isinstance(authentication, Mapping)
        and authentication.get("evidence_scope") == "PUBLIC_PROJECTION"
    )
    organization_complete = (
        isinstance(authentication, Mapping)
        and authentication.get("organization_complete") is True
    )
    scope_conflict = public_projection and organization_complete
    subinventory_states: dict[str, str] = {}
    counts: dict[str, int | None] = {}
    items_by_kind: dict[str, list[dict[str, Any]]] = {}
    invalid_ids: list[str] = []
    duplicate_ids: list[str] = []
    invalid_revisions: list[str] = []
    visibility_unknown: list[str] = []
    for kind in REQUIRED_ASSET_KINDS:
        raw = assets.get(kind)
        if not isinstance(raw, Mapping) or type(raw.get("ok")) is not bool:
            kind_state = "DIVERGENT"
            subinventory_states[kind] = kind_state
            counts[kind] = None
            items_by_kind[kind] = []
            continue
        if raw.get("ok") is False:
            kind_state = (
                "DIVERGENT"
                if raw.get("diagnostic_state") == "INVALID_RESPONSE"
                else "UNAVAILABLE"
            )
            subinventory_states[kind] = kind_state
            counts[kind] = None
            raw_items = raw.get("items")
            items_by_kind[kind] = (
                [dict(item) for item in raw_items]
                if isinstance(raw_items, list)
                and all(isinstance(item, Mapping) for item in raw_items)
                else []
            )
            continue
        count = _nonnegative_int(raw.get("count"))
        raw_items = raw.get("items")
        if (
            count is None
            or not isinstance(raw_items, list)
            or any(not isinstance(item, Mapping) for item in raw_items)
        ):
            kind_state = "DIVERGENT"
            subinventory_states[kind] = kind_state
            counts[kind] = None
            items_by_kind[kind] = []
            continue
        normalized_items = [dict(item) for item in raw_items]
        seen: set[str] = set()
        kind_divergent = count != len(normalized_items)
        kind_unavailable = raw.get("error") is not None
        identity_field = "slug" if kind == "collections" else "id"
        for index, item in enumerate(normalized_items):
            identity = item.get(identity_field)
            safe_label = f"{kind}[{index}]"
            if not isinstance(identity, str) or HF_ID.fullmatch(identity) is None:
                invalid_ids.append(safe_label)
                kind_divergent = True
                continue
            safe_label = identity
            if identity in seen:
                duplicate_ids.append(identity)
                kind_divergent = True
            seen.add(identity)
            if type(item.get("private")) is not bool:
                visibility_unknown.append(safe_label)
                kind_divergent = True
            if kind in REPO_BACKED_ASSET_KINDS and not _valid_sha(item.get("sha")):
                invalid_revisions.append(safe_label)
                kind_divergent = True
            if kind == "collections" and (
                item.get("complete") is not True or item.get("detail_error") is not None
            ):
                kind_unavailable = True
            if kind == "buckets" and (
                item.get("discovered_via") == "collection"
                or item.get("tree_state") != "OBSERVED"
                or item.get("tree_error") is not None
            ):
                kind_unavailable = True
        if count != len(seen):
            kind_divergent = True
        kind_state = (
            "DIVERGENT"
            if kind_divergent
            else "UNAVAILABLE"
            if kind_unavailable
            else "MEASURED"
        )
        subinventory_states[kind] = kind_state
        counts[kind] = count if kind_state == "MEASURED" else None
        items_by_kind[kind] = sorted(
            normalized_items,
            key=lambda item: str(item.get(identity_field) or ""),
        )

    # Asset counts are organization totals in this artifact.  A public
    # projection, or an absent completeness witness, can report a useful
    # subset but cannot establish those totals.  Preserve independently
    # divergent asset diagnostics while withholding unproven exact counts.
    if scope_conflict:
        for kind in REQUIRED_ASSET_KINDS:
            subinventory_states[kind] = "DIVERGENT"
            counts[kind] = None
    elif not organization_complete:
        for kind in REQUIRED_ASSET_KINDS:
            if subinventory_states[kind] == "MEASURED":
                subinventory_states[kind] = "UNAVAILABLE"
                counts[kind] = None
    states = set(subinventory_states.values())
    state = (
        "DIVERGENT"
        if "DIVERGENT" in states
        else "UNAVAILABLE"
        if "UNAVAILABLE" in states
        else "MEASURED"
    )
    public_space_ids: list[str] = []
    missing_licenses: list[str] = []
    running_unbound: list[str] = []
    non_running: list[str] = []
    for kind in ("models", "datasets", "spaces"):
        for index, item in enumerate(items_by_kind[kind]):
            raw_id = item.get("id")
            item_id = (
                raw_id
                if isinstance(raw_id, str) and HF_ID.fullmatch(raw_id) is not None
                else f"{kind}[{index}]"
            )
            if item.get("license_declared") is not True:
                missing_licenses.append(item_id)
    space_identity_complete = subinventory_states.get("spaces") == "MEASURED"
    seen_space_ids: set[str] = set()
    for index, item in enumerate(items_by_kind["spaces"]):
        raw_id = item.get("id")
        if (
            not isinstance(raw_id, str)
            or HF_ID.fullmatch(raw_id) is None
            or raw_id in seen_space_ids
        ):
            space_identity_complete = False
            item_id = f"spaces[{index}]"
        else:
            item_id = raw_id
            seen_space_ids.add(raw_id)
        private = item.get("private")
        if type(private) is bool and not private and space_identity_complete:
            public_space_ids.append(item_id)
        if item.get("sdk") != "static":
            if item.get("stage") != "RUNNING":
                non_running.append(item_id)
            elif not _dynamic_space_bound(item):
                running_unbound.append(item_id)

    if state == "DIVERGENT":
        release_gate = "DIVERGENT"
    elif state == "UNAVAILABLE":
        release_gate = "UNAVAILABLE"
    elif missing_licenses or running_unbound or non_running:
        release_gate = "BLOCKED"
    else:
        release_gate = "MEASURED"
    return (
        {
            "state": state,
            "release_gate": release_gate,
            "counts": counts,
            "subinventory_states": subinventory_states,
            "public_space_count": (
                len(public_space_ids)
                if not visibility_unknown and space_identity_complete
                else None
            ),
            "public_space_ids": sorted(public_space_ids),
            "invalid_asset_ids": sorted(set(invalid_ids)),
            "duplicate_asset_ids": sorted(set(duplicate_ids)),
            "invalid_revision_ids": sorted(set(invalid_revisions)),
            "missing_license_ids": sorted(set(missing_licenses)),
            "visibility_unknown_ids": sorted(set(visibility_unknown)),
            "running_unbound_spaces": sorted(set(running_unbound)),
            "non_running_dynamic_spaces": sorted(set(non_running)),
            "reason": (
                "Hugging Face public projection is a public subset, not a complete organization inventory."
                if public_projection and not scope_conflict
                else "Hugging Face public projection conflicts with a complete-organization claim."
                if scope_conflict
                else "Hugging Face organization completeness is unverified."
                if not organization_complete
                else "Hugging Face counts, identity, visibility, and runtime evidence were recomputed from asset items."
            ),
        },
        items_by_kind,
        subinventory_states,
    )


def _load_policy(policy: Mapping[str, Any] | None) -> tuple[str, dict[str, Any], str]:
    if not isinstance(policy, Mapping):
        return "UNAVAILABLE", {}, POLICY_UNAVAILABLE_REASON
    if set(policy) != {
        "schema",
        "status",
        "domain_roles",
        "public_space_policy",
    }:
        return "DIVERGENT", {}, POLICY_DIVERGENT_REASON
    public = policy.get("public_space_policy")
    roles = policy.get("domain_roles")
    if (
        not isinstance(public, Mapping)
        or set(public)
        != {
            "normal_limit",
            "normal_allowlist_state",
            "exceptions",
        }
        or not isinstance(roles, list)
    ):
        return "DIVERGENT", {}, POLICY_DIVERGENT_REASON
    exceptions = public.get("exceptions")
    if not isinstance(exceptions, list):
        return "DIVERGENT", {}, POLICY_DIVERGENT_REASON
    exception_keys = set(LOCKED_KILLINCHU_EXCEPTION)
    if any(
        not isinstance(item, Mapping) or set(item) != exception_keys
        for item in exceptions
    ):
        return "DIVERGENT", {}, POLICY_DIVERGENT_REASON
    if any(not _valid_exception_chronology(item) for item in exceptions):
        return "DIVERGENT", {}, POLICY_DIVERGENT_REASON
    role_keys = {"domain", "role", "source"}
    if any(not isinstance(item, Mapping) or set(item) != role_keys for item in roles):
        return "DIVERGENT", {}, POLICY_DIVERGENT_REASON
    normalized = {
        "schema": policy.get("schema"),
        "status": policy.get("status"),
        "domain_roles": [
            {field: item.get(field) for field in ("domain", "role", "source")}
            for item in roles
        ],
        "public_space_policy": {
            "normal_limit": public.get("normal_limit"),
            "normal_allowlist_state": public.get("normal_allowlist_state"),
            "exceptions": [
                {field: item.get(field) for field in LOCKED_KILLINCHU_EXCEPTION}
                for item in exceptions
            ],
        },
    }
    if normalized != LOCKED_POLICY:
        return "DIVERGENT", {}, POLICY_DIVERGENT_REASON
    return "MEASURED", normalized, POLICY_MEASURED_REASON


def _public_space_policy(
    hf: Mapping[str, Any],
    policy_state: str,
    policy: Mapping[str, Any],
    assessed_at: dt.datetime,
) -> dict[str, Any]:
    if policy_state != "MEASURED":
        return {
            "state": policy_state,
            "normal_limit": None,
            "normal_allowlist_state": None,
            "authorized_exception_count": None,
            "expired_exception_count": None,
            "authorized_maximum": None,
            "public_space_count": hf.get("public_space_count"),
            "killinchu_observed": None,
            "killinchu_exception": None,
            "reason": "The five-plus-one policy cannot be evaluated without valid policy evidence.",
        }
    public = policy["public_space_policy"]
    exceptions = public["exceptions"]
    normal_limit = public["normal_limit"]
    active_exceptions: list[dict[str, Any]] = []
    expired_exceptions: list[dict[str, Any]] = []
    future_exceptions: list[dict[str, Any]] = []
    invalid_exceptions: list[dict[str, Any]] = []
    for exception in exceptions:
        decision_date = _parse_timestamp(f"{exception['decision_date']}T00:00:00Z")
        review_due = _parse_timestamp(f"{exception['review_due']}T23:59:59Z")
        if decision_date is None or review_due is None or decision_date > review_due:
            invalid_exceptions.append(exception)
        elif assessed_at < decision_date:
            future_exceptions.append(exception)
        elif assessed_at > review_due:
            expired_exceptions.append(exception)
        else:
            active_exceptions.append(exception)
    public_count = hf.get("public_space_count")
    public_ids = hf.get("public_space_ids")
    public_ids_valid = isinstance(public_ids, list) and all(
        isinstance(item, str) for item in public_ids
    )
    if public_ids_valid and LOCKED_KILLINCHU_EXCEPTION["surface"] in public_ids:
        killinchu_observed = True
    elif type(public_count) is int and public_ids_valid:
        killinchu_observed = False
    else:
        killinchu_observed = None

    exception_is_active = any(
        item == LOCKED_KILLINCHU_EXCEPTION for item in active_exceptions
    )
    if not exception_is_active:
        authorized_exception_count = 0
    elif killinchu_observed is None:
        authorized_exception_count = None
    else:
        authorized_exception_count = 1 if killinchu_observed else 0
    authorized_maximum = (
        normal_limit + authorized_exception_count
        if type(authorized_exception_count) is int
        else None
    )
    if invalid_exceptions:
        state = "DIVERGENT"
        reason = "A conditional public-Space exception has invalid date chronology."
    elif future_exceptions:
        state = "DIVERGENT"
        reason = "A conditional public-Space exception is not yet effective."
    elif expired_exceptions:
        state = "DIVERGENT"
        reason = "A conditional public-Space exception passed its review deadline."
    elif type(public_count) is not int:
        state = "UNAVAILABLE"
        reason = "Public Space visibility is incomplete."
    elif type(authorized_maximum) is not int:
        state = "UNAVAILABLE"
        reason = "Public Space exception visibility is incomplete."
    elif public_count > authorized_maximum:
        state = "DIVERGENT"
        reason = f"Observed {public_count} public Spaces exceeds the five-plus-one maximum of {authorized_maximum}."
    elif public.get("normal_allowlist_state") != "MEASURED":
        state = "BLOCKED"
        reason = "The normal five-Space allowlist is not machine-readable."
    else:
        state = "MEASURED"
        reason = "Observed public Space footprint satisfies the versioned policy."
    killinchu = next(
        (item for item in exceptions if item["surface"].lower().endswith("/killinchu")),
        None,
    )
    return {
        "state": state,
        "normal_limit": normal_limit,
        "normal_allowlist_state": public.get("normal_allowlist_state"),
        "authorized_exception_count": authorized_exception_count,
        "expired_exception_count": len(expired_exceptions),
        "authorized_maximum": authorized_maximum,
        "public_space_count": public_count,
        "killinchu_observed": killinchu_observed,
        "killinchu_exception": killinchu,
        "reason": reason,
    }


def _benchmark_from_summaries(
    dataset: Mapping[str, Any] | None,
    space: Mapping[str, Any] | None,
    dataset_state: str,
    space_state: str,
) -> dict[str, Any]:
    if "DIVERGENT" in {dataset_state, space_state}:
        state = "DIVERGENT"
        reason = "Benchmark dataset or Space subinventory is divergent."
    elif "UNAVAILABLE" in {dataset_state, space_state}:
        state = "UNAVAILABLE"
        reason = "Benchmark dataset or Space subinventory is unavailable."
    elif {dataset_state, space_state} != {"MEASURED"}:
        state = "DIVERGENT"
        reason = "Benchmark subinventory states are invalid."
    elif dataset is None or space is None:
        state = "UNAVAILABLE"
        reason = "Benchmark dataset and Space were not both observed."
    elif (
        dataset.get("id") != "SZLHOLDINGS/governed-agent-bench"
        or not _valid_sha(dataset.get("sha"))
        or dataset.get("private") is not False
    ):
        state = "DIVERGENT"
        reason = "Benchmark dataset identity, revision, or visibility is divergent."
    elif (
        dataset.get("license_declared") is not True
        or dataset.get("card_state") != "COMPLETE"
    ):
        state = "BLOCKED"
        reason = "Benchmark dataset lacks complete license or card evidence."
    elif (
        space.get("id") != "SZLHOLDINGS/governed-agent-bench"
        or not _valid_sha(space.get("sha"))
        or space.get("private") is not False
    ):
        state = "DIVERGENT"
        reason = "Benchmark Space identity, revision, or visibility is divergent."
    elif space.get("stage") != "RUNNING":
        state = "BLOCKED"
        reason = (
            "Benchmark Space is not RUNNING; source publication does not prove "
            "a live leaderboard."
        )
    elif not _dynamic_space_bound(space):
        state = "BLOCKED"
        reason = (
            "Benchmark Space lacks primitive exact-source, health, "
            "and build-info runtime evidence."
        )
    elif (
        not _valid_http(space.get("leaderboard_http"), exact=200)
        or not _valid_sha(space.get("eval_output_revision"))
        or not isinstance(space.get("eval_output_sha256"), str)
        or SHA64.fullmatch(space["eval_output_sha256"]) is None
        or not isinstance(space.get("eval_receipt_id"), str)
        or re.fullmatch(r"[A-Za-z0-9._:/-]{1,200}", space["eval_receipt_id"]) is None
        or space.get("eval_dataset_revision") != dataset.get("sha")
        or space.get("eval_space_revision") != space.get("canonical_source_revision")
        or space.get("eval_reproduction_state") != "VERIFIED"
    ):
        state = "BLOCKED"
        reason = (
            "Benchmark leaderboard and immutable cross-bound evaluation receipt "
            "were not both witnessed."
        )
    else:
        state = "MEASURED"
        reason = (
            "Benchmark dataset, live source-bound leaderboard, and immutable "
            "cross-bound evaluation receipt were observed."
        )
    return {
        "state": state,
        "dataset": None if dataset is None else dict(dataset),
        "space": None if space is None else dict(space),
        "reason": reason,
    }


def _governed_agent_bench(
    items: Mapping[str, list[dict[str, Any]]],
    subinventory_states: Mapping[str, str],
) -> dict[str, Any]:
    dataset = next(
        (
            item
            for item in items.get("datasets", [])
            if item.get("id") == "SZLHOLDINGS/governed-agent-bench"
        ),
        None,
    )
    space = next(
        (
            item
            for item in items.get("spaces", [])
            if item.get("id") == "SZLHOLDINGS/governed-agent-bench"
        ),
        None,
    )
    dataset_summary = _benchmark_dataset_summary(
        dataset,
        subinventory_states.get("datasets", "UNAVAILABLE"),
    )
    space_summary = _benchmark_space_summary(
        space,
        subinventory_states.get("spaces", "UNAVAILABLE"),
    )
    return _benchmark_from_summaries(
        dataset_summary,
        space_summary,
        subinventory_states.get("datasets", "UNAVAILABLE"),
        subinventory_states.get("spaces", "UNAVAILABLE"),
    )


def _blank_governance_evidence(state: str) -> dict[str, Any]:
    return {
        "state": state,
        "schema": None,
        "certification": None,
        "overall_status": None,
        "summary": None,
        "controls": [],
    }


def _governance_evidence(report: Mapping[str, Any]) -> dict[str, Any]:
    governance = report.get("governance")
    if not isinstance(governance, Mapping):
        return _blank_governance_evidence("UNAVAILABLE")
    if (
        governance.get("schema") != "szl.estate-governance-evaluation/v1"
        or governance.get("certification") != "NOT_A_CERTIFICATION"
        or not isinstance(governance.get("controls"), list)
    ):
        return _blank_governance_evidence("DIVERGENT")
    controls: list[dict[str, str]] = []
    seen: set[str] = set()
    for raw in governance["controls"]:
        if not isinstance(raw, Mapping):
            return _blank_governance_evidence("DIVERGENT")
        control_id = raw.get("id")
        status = raw.get("status")
        severity = raw.get("severity")
        if (
            not isinstance(control_id, str)
            or control_id not in GOVERNANCE_CONTROL_SEVERITIES
            or control_id in seen
            or not isinstance(status, str)
            or status not in CONTROL_STATUSES
            or severity != GOVERNANCE_CONTROL_SEVERITIES.get(control_id)
            or not isinstance(raw.get("summary"), str)
            or not raw.get("summary")
        ):
            return _blank_governance_evidence("DIVERGENT")
        seen.add(control_id)
        controls.append({"id": control_id, "status": status, "severity": str(severity)})
    if seen != set(GOVERNANCE_CONTROL_SEVERITIES):
        return _blank_governance_evidence("DIVERGENT")
    derived = {
        status: sum(1 for control in controls if control["status"] == status)
        for status in CONTROL_STATUSES
    }
    summary = governance.get("summary")
    if (
        not isinstance(summary, Mapping)
        or set(summary) != CONTROL_STATUSES
        or any(
            _nonnegative_int(summary.get(status)) != derived[status]
            for status in CONTROL_STATUSES
        )
    ):
        return _blank_governance_evidence("DIVERGENT")
    expected_overall = (
        "FAIL" if derived["FAIL"] else "UNKNOWN" if derived["UNKNOWN"] else "PASS"
    )
    if governance.get("overall_status") != expected_overall:
        return _blank_governance_evidence("DIVERGENT")
    return {
        "state": "MEASURED",
        "schema": "szl.estate-governance-evaluation/v1",
        "certification": "NOT_A_CERTIFICATION",
        "overall_status": expected_overall,
        "summary": {status: derived[status] for status in sorted(CONTROL_STATUSES)},
        "controls": sorted(controls, key=lambda item: item["id"]),
    }


def _governance_evidence_valid(evidence: Mapping[str, Any]) -> bool:
    if set(evidence) != {
        "state",
        "schema",
        "certification",
        "overall_status",
        "summary",
        "controls",
    }:
        return False
    state = evidence.get("state")
    if state in {"UNAVAILABLE", "DIVERGENT"}:
        return dict(evidence) == _blank_governance_evidence(str(state))
    if state != "MEASURED":
        return False
    if (
        evidence.get("schema") != "szl.estate-governance-evaluation/v1"
        or evidence.get("certification") != "NOT_A_CERTIFICATION"
        or evidence.get("overall_status") not in {"PASS", "FAIL", "UNKNOWN"}
        or not isinstance(evidence.get("summary"), Mapping)
        or set(evidence["summary"]) != CONTROL_STATUSES
        or not isinstance(evidence.get("controls"), list)
    ):
        return False
    controls = evidence["controls"]
    ids: list[str] = []
    for control in controls:
        if not _exact_keys(control, {"id", "status", "severity"}):
            return False
        control_id = control.get("id")
        if (
            not isinstance(control_id, str)
            or control_id not in GOVERNANCE_CONTROL_SEVERITIES
            or control.get("status") not in CONTROL_STATUSES
            or control.get("severity") != GOVERNANCE_CONTROL_SEVERITIES[control_id]
        ):
            return False
        ids.append(control_id)
    if ids != sorted(GOVERNANCE_CONTROL_SEVERITIES):
        return False
    derived = {
        status: sum(1 for control in controls if control["status"] == status)
        for status in CONTROL_STATUSES
    }
    if any(
        evidence["summary"].get(status) != derived[status]
        for status in CONTROL_STATUSES
    ):
        return False
    expected_overall = (
        "FAIL" if derived["FAIL"] else "UNKNOWN" if derived["UNKNOWN"] else "PASS"
    )
    return evidence.get("overall_status") == expected_overall


def _ledgers_from_governance_evidence(
    evidence: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], str, str]:
    if not _governance_evidence_valid(evidence) or evidence.get("state") == "DIVERGENT":
        divergent = {
            "state": "DIVERGENT",
            "entries": [],
            "reason": "Governance evaluation contract is malformed.",
        }
        return (
            divergent,
            dict(divergent),
            "DIVERGENT",
            "Governance evaluation contract is malformed.",
        )
    if evidence.get("state") == "UNAVAILABLE":
        unavailable = {
            "state": "UNAVAILABLE",
            "entries": [],
            "reason": "Governance evaluation is unavailable.",
        }
        return (
            unavailable,
            dict(unavailable),
            "UNAVAILABLE",
            "Governance evaluation is unavailable.",
        )
    controls = evidence["controls"]
    corrections = [
        {
            "id": control["id"],
            "status": "OPEN",
            "severity": control["severity"],
            "summary": (
                f"{control['id']} reported FAIL in the supplied governance evaluation."
            ),
        }
        for control in controls
        if control["status"] == "FAIL"
    ]
    overclaims = [
        {
            "id": control["id"],
            "status": "OPEN",
            "severity": control["severity"],
            "summary": f"{control['id']} reported UNKNOWN; PASS must not be claimed.",
        }
        for control in controls
        if control["status"] == "UNKNOWN"
    ]
    correction_state = "BLOCKED" if corrections else "MEASURED"
    overclaim_state = "UNAVAILABLE" if overclaims else "MEASURED"
    aggregate = (
        "BLOCKED" if corrections else "UNAVAILABLE" if overclaims else "MEASURED"
    )
    return (
        {
            "state": correction_state,
            "entries": corrections,
            "reason": "FAIL controls become open corrections.",
        },
        {
            "state": overclaim_state,
            "entries": overclaims,
            "reason": "UNKNOWN controls become explicit overclaim boundaries.",
        },
        aggregate,
        "Governance labels were recomputed from individual controls.",
    )


def _freshness(report: Mapping[str, Any], assessed_at: dt.datetime) -> dict[str, Any]:
    generated = _parse_timestamp(report.get("generated_at"))
    if generated is None:
        return {
            "state": "DIVERGENT",
            "age_seconds": None,
            "reason": "Census generated_at is invalid.",
        }
    try:
        delta = (assessed_at - generated).total_seconds()
    except (OverflowError, OSError):
        return {
            "state": "DIVERGENT",
            "age_seconds": None,
            "reason": "Census timestamp is outside the supported range.",
        }
    if delta < -MAX_FUTURE_SKEW_SECONDS:
        return {
            "state": "DIVERGENT",
            "age_seconds": None,
            "reason": "Census timestamp is implausibly in the future.",
        }
    age = max(0, int(delta))
    if age > MAX_REPORT_AGE_SECONDS:
        return {
            "state": "STALE",
            "age_seconds": age,
            "reason": "Census is older than the 24-hour diligence window.",
        }
    return {
        "state": "MEASURED",
        "age_seconds": age,
        "reason": "Census is inside the 24-hour diligence window.",
    }


def _public_snapshot_binding(
    report: Mapping[str, Any],
    raw_public_bytes: bytes | None,
    receipt: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Bind supplied public bytes only; do not authenticate private evidence."""

    raw_digest = (
        hashlib.sha256(raw_public_bytes).hexdigest()
        if isinstance(raw_public_bytes, bytes)
        and len(raw_public_bytes) <= MAX_JSON_BYTES
        else None
    )
    binding = {
        "state": "UNAVAILABLE" if receipt is None else "DIVERGENT",
        "reason": (
            PUBLIC_RECEIPT_UNAVAILABLE_REASON
            if receipt is None
            else PUBLIC_RECEIPT_DIVERGENT_REASON
        ),
        "raw_public_sha256": raw_digest,
        "receipt_public_sha256": None,
        "collection_id": None,
        "receipt_collection_id": None,
    }
    if receipt is None:
        return binding
    if not isinstance(receipt, Mapping) or not isinstance(raw_public_bytes, bytes):
        return binding
    try:
        parsed = strict_parse_json_bytes(raw_public_bytes, source="public census")
        if canonical_bytes(parsed) != canonical_bytes(report):
            return binding
        public_snapshot = receipt.get("public_snapshot")
        collection = parsed.get("collection")
        if isinstance(collection, Mapping):
            collection_id = collection.get("id")
            if isinstance(collection_id, str) and COLLECTION_ID.fullmatch(
                collection_id
            ):
                binding["collection_id"] = collection_id
        if isinstance(public_snapshot, Mapping):
            claimed_digest = public_snapshot.get("sha256")
            claimed_collection = public_snapshot.get("collection_id")
            if _valid_sha256(claimed_digest):
                binding["receipt_public_sha256"] = claimed_digest
            if isinstance(claimed_collection, str) and COLLECTION_ID.fullmatch(
                claimed_collection
            ):
                binding["receipt_collection_id"] = claimed_collection
        if (
            parsed.get("projection_schema") != "szl.estate-public-projection/v1"
            or parsed.get("exposure") != "public"
            or type(parsed.get("schema_version")) is not int
            or parsed["schema_version"] != REPORT_SCHEMA_VERSION
            or not isinstance(collection, Mapping)
            or collection.get("schema") != "szl.census-collection/v1"
            or binding["collection_id"] is None
            or receipt.get("schema") != "szl.estate-census-receipt/v1"
            or not isinstance(public_snapshot, Mapping)
            or set(public_snapshot) != {"state", "sha256", "collection_id"}
            or public_snapshot.get("state") != "FRESH_COLLECTION_BOUND"
            or binding["receipt_public_sha256"] != raw_digest
            or binding["receipt_collection_id"] != binding["collection_id"]
            or _sensitive_text_paths(receipt)
        ):
            return binding
    except (DiligenceError, RecursionError, TypeError, ValueError):
        return binding
    binding["state"] = "MEASURED"
    binding["reason"] = PUBLIC_RECEIPT_MEASURED_REASON
    return binding


def _overall_state(requirements: Mapping[str, Mapping[str, Any]]) -> str:
    states = [value.get("state") for value in requirements.values()]
    if "DIVERGENT" in states:
        return "DIVERGENT"
    if "STALE" in states:
        return "STALE"
    if "BLOCKED" in states or "UNAVAILABLE" in states:
        return "BLOCKED"
    return "MEASURED"


def compile_diligence(
    report: Mapping[str, Any],
    *,
    compiler_source_revision: str | None,
    policy: Mapping[str, Any] | None,
    as_of: str | dt.datetime | None = None,
    raw_public_bytes: bytes | None = None,
    public_snapshot_receipt: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Compile one deterministic investor-diligence artifact."""

    if not isinstance(report, Mapping):
        raise DiligenceError("census report root must be an object")
    if (
        "exposure" in report and report.get("exposure") != "public"
    ) or _has_private_inventory(report):
        raise DiligenceError("private census inventory cannot enter diligence output")
    _walk(report)
    _walk(policy)
    assessed_at = _as_of(as_of)
    compiler_verified = _verify_compiler_source_revision(compiler_source_revision)
    source_state, source_revision, source_reason = _state_for_revision(
        compiler_source_revision,
        verified=compiler_verified,
    )
    schema_state = (
        "MEASURED"
        if report.get("schema_version") == REPORT_SCHEMA_VERSION
        else "DIVERGENT"
    )
    freshness = _freshness(report, assessed_at)
    public_binding = _public_snapshot_binding(
        report, raw_public_bytes, public_snapshot_receipt
    )
    sources, source_states = _source_summary(report)
    github = _github_inventory(report, source_states.get("github", "UNAVAILABLE"))
    huggingface, hf_items, hf_states = _hf_inventory(
        report,
        source_states.get("huggingface", "UNAVAILABLE"),
    )
    policy_state, normalized_policy, policy_reason = _load_policy(policy)
    public_space_policy = _public_space_policy(
        huggingface,
        policy_state,
        normalized_policy,
        assessed_at,
    )
    benchmark = _governed_agent_bench(hf_items, hf_states)
    governance_evidence = _governance_evidence(report)
    (
        corrections,
        overclaims,
        governance_state,
        governance_reason,
    ) = _ledgers_from_governance_evidence(governance_evidence)

    target_roles = (
        normalized_policy.get("domain_roles", []) if normalized_policy else []
    )
    product_proof = {
        "state": "UNAVAILABLE",
        "targets": target_roles,
        "reason": PRODUCT_PROOF_REASON,
    }
    route_tabs = {
        "state": "UNAVAILABLE",
        "routes": None,
        "tabs": None,
        "reason": ROUTE_TABS_REASON,
    }
    cost_posture = {
        "state": "UNAVAILABLE",
        "spaces_with_cost_evidence": None,
        "reason": COST_POSTURE_REASON,
    }
    model_promotion = {
        "state": "UNAVAILABLE",
        "reason": MODEL_PROMOTION_REASON,
    }
    governed_mcp = {
        "state": "UNAVAILABLE",
        "observed_flagship_endpoints": None,
        "reason": GOVERNED_MCP_REASON,
    }

    requirements: dict[str, dict[str, str]] = {
        "census_schema": {
            "state": schema_state,
            "reason": "Schema-v2 census is required.",
        },
        "compiler_source": {"state": source_state, "reason": source_reason},
        "correction_and_overclaim_ledger": {
            "state": governance_state,
            "reason": governance_reason,
        },
        "governed_agent_bench": {
            "state": benchmark["state"],
            "reason": benchmark["reason"],
        },
        "governed_mcp": {
            "state": governed_mcp["state"],
            "reason": governed_mcp["reason"],
        },
        "github_inventory": {"state": github["state"], "reason": github["reason"]},
        "github_release_gate": {
            "state": github["release_gate"],
            "reason": github["reason"],
        },
        "hf_inventory": {
            "state": huggingface["state"],
            "reason": huggingface["reason"],
        },
        "hf_release_gate": {
            "state": huggingface["release_gate"],
            "reason": huggingface["reason"],
        },
        "model_promotion": {
            "state": model_promotion["state"],
            "reason": model_promotion["reason"],
        },
        "product_proof_roles": {
            "state": product_proof["state"],
            "reason": product_proof["reason"],
        },
        "public_space_policy": {
            "state": public_space_policy["state"],
            "reason": public_space_policy["reason"],
        },
        "public_snapshot_receipt": {
            "state": public_binding["state"],
            "reason": public_binding["reason"],
        },
        "route_tab_inventory": {
            "state": route_tabs["state"],
            "reason": route_tabs["reason"],
        },
        "snapshot_freshness": {
            "state": freshness["state"],
            "reason": freshness["reason"],
        },
        "space_cost_posture": {
            "state": cost_posture["state"],
            "reason": cost_posture["reason"],
        },
        "target_policy": {"state": policy_state, "reason": policy_reason},
        **{
            name: {"state": "UNAVAILABLE", "reason": reason}
            for name, reason in FIXED_UNAVAILABLE_REQUIREMENTS.items()
        },
    }
    requirements = dict(sorted(requirements.items()))
    overall = _overall_state(requirements)
    gaps = [
        {"requirement": name, "state": item["state"], "reason": item["reason"]}
        for name, item in requirements.items()
        if item["state"] != "MEASURED"
    ]
    artifact: dict[str, Any] = {
        "schema": ARTIFACT_SCHEMA,
        "state": overall,
        "claim_boundary": CLAIM_BOUNDARY,
        "assessed_at": _timestamp(assessed_at),
        "source_binding": {
            "state": source_state,
            "compiler_revision": source_revision,
            "compiler_revision_verified": compiler_verified,
            "census_sha256": semantic_sha256(_binding_view(report)),
            "policy_sha256": (
                semantic_sha256(normalized_policy) if normalized_policy else None
            ),
            "policy_state": policy_state,
            "census_schema_version": report.get("schema_version"),
            "census_generated_at": report.get("generated_at"),
            "census_age_seconds": freshness["age_seconds"],
        },
        "public_snapshot_binding": public_binding,
        "sources": sources,
        "requirements": requirements,
        "inventory": {"github": github, "huggingface": huggingface},
        "product_proof_roles": product_proof,
        "public_space_policy": public_space_policy,
        "governed_agent_bench": benchmark,
        "governed_mcp": governed_mcp,
        "model_promotion": model_promotion,
        "route_tab_inventory": route_tabs,
        "space_cost_posture": cost_posture,
        "governance_evidence": governance_evidence,
        "correction_ledger": corrections,
        "overclaim_ledger": overclaims,
        "summary": {
            "github_repositories": github["repository_count"],
            "github_active_repositories": github["active_count"],
            "github_ci_failures": github["ci"]["failure"],
            "hf_models": huggingface["counts"]["models"],
            "hf_datasets": huggingface["counts"]["datasets"],
            "hf_spaces": huggingface["counts"]["spaces"],
            "hf_public_spaces": huggingface["public_space_count"],
            "open_corrections": (
                len(corrections["entries"])
                if corrections["state"] in {"MEASURED", "BLOCKED"}
                else None
            ),
            "open_overclaims": (
                len(overclaims["entries"])
                if overclaims["entries"] or overclaims["state"] == "MEASURED"
                else None
            ),
        },
        "gaps": gaps,
    }
    sensitive_paths = _sensitive_text_paths(artifact)
    if sensitive_paths:
        raise DiligenceError("sensitive output text is forbidden")
    artifact["digest_sha256"] = hashlib.sha256(canonical_bytes(artifact)).hexdigest()
    return artifact


def _exact_keys(value: Any, expected: set[str]) -> bool:
    return isinstance(value, Mapping) and set(value) == expected


def _nullable_count(value: Any) -> bool:
    return value is None or _nonnegative_int(value) is not None


def _sorted_unique_strings(value: Any) -> bool:
    return (
        isinstance(value, list)
        and all(isinstance(item, str) and item for item in value)
        and value == sorted(set(value))
    )


def _state_reason(value: Any, *, extra: set[str] | None = None) -> bool:
    keys = {"state", "reason"} | (extra or set())
    return bool(
        _exact_keys(value, keys)
        and value.get("state") in TRUTH_STATES
        and isinstance(value.get("reason"), str)
        and value.get("reason")
    )


def _validate_ledger(value: Any) -> bool:
    if not _state_reason(value, extra={"entries"}) or not isinstance(
        value.get("entries"), list
    ):
        return False
    ids: list[str] = []
    for entry in value["entries"]:
        if not _exact_keys(entry, {"id", "status", "severity", "summary"}):
            return False
        control_id = entry.get("id")
        if (
            not isinstance(control_id, str)
            or control_id not in GOVERNANCE_CONTROL_SEVERITIES
            or entry.get("status") != "OPEN"
            or entry.get("severity") != GOVERNANCE_CONTROL_SEVERITIES[control_id]
            or not isinstance(entry.get("summary"), str)
            or not entry.get("summary")
        ):
            return False
        ids.append(control_id)
    return ids == sorted(set(ids))


def _governance_artifact_state(
    corrections: Mapping[str, Any], overclaims: Mapping[str, Any]
) -> str:
    states = {corrections.get("state"), overclaims.get("state")}
    if "DIVERGENT" in states:
        return "DIVERGENT"
    if corrections.get("state") == "BLOCKED":
        return "BLOCKED"
    if overclaims.get("entries"):
        return "UNAVAILABLE"
    if states == {"MEASURED"}:
        return "MEASURED"
    return "UNAVAILABLE"


def _benchmark_dataset_shape(value: Any) -> bool:
    return isinstance(value, Mapping) and value == _benchmark_dataset_summary(
        value, "MEASURED"
    )


def _benchmark_space_shape(value: Any) -> bool:
    return isinstance(value, Mapping) and value == _benchmark_space_summary(
        value, "MEASURED"
    )


def validate_artifact(value: Any) -> list[str]:
    """Validate renderer dependencies and independently derived invariants."""

    errors: list[str] = []
    try:
        if not _exact_keys(value, ARTIFACT_KEYS):
            return ["root"]
        _walk(value)
        if _sensitive_text_paths(value):
            errors.append("sensitive_text")
        if value.get("schema") != ARTIFACT_SCHEMA:
            errors.append("schema")
        if value.get("claim_boundary") != CLAIM_BOUNDARY:
            errors.append("claim_boundary")
        assessed_at = _parse_timestamp(value.get("assessed_at"))
        if assessed_at is None:
            errors.append("assessed_at")
            assessed_at = dt.datetime(1970, 1, 1, tzinfo=dt.UTC)

        binding_keys = {
            "state",
            "compiler_revision",
            "compiler_revision_verified",
            "census_sha256",
            "policy_sha256",
            "policy_state",
            "census_schema_version",
            "census_generated_at",
            "census_age_seconds",
        }
        binding = value.get("source_binding")
        if not _exact_keys(binding, binding_keys):
            errors.append("source_binding")
            binding = {}
        revision = binding.get("compiler_revision")
        verified_claim = binding.get("compiler_revision_verified")
        if type(verified_claim) is not bool:
            errors.append("source_binding.compiler_revision_verified")
            verified_claim = False
        verified = (
            _verify_compiler_source_revision(revision)
            if verified_claim is True
            else False
        )
        expected_source_state, normalized_revision, source_reason = _state_for_revision(
            revision,
            verified=verified,
        )
        if revision != normalized_revision:
            errors.append("source_binding.compiler_revision")
        if binding.get("state") != expected_source_state:
            errors.append("source_binding.state")
        if verified_claim != verified:
            errors.append("source_binding.compiler_revision_verified")
        if verified_claim != (expected_source_state == "MEASURED"):
            errors.append("source_binding.compiler_revision_verified")
        census_sha = binding.get("census_sha256")
        if not _valid_sha256(census_sha):
            errors.append("source_binding.census_sha256")
        policy_state = binding.get("policy_state")
        if policy_state not in {"MEASURED", "UNAVAILABLE", "DIVERGENT"}:
            errors.append("source_binding.policy_state")
            policy_state = "DIVERGENT"
        expected_policy_sha = (
            semantic_sha256(LOCKED_POLICY) if policy_state == "MEASURED" else None
        )
        if binding.get("policy_sha256") != expected_policy_sha:
            errors.append("source_binding.policy_sha256")
        schema_version = binding.get("census_schema_version")
        if schema_version is not None and _nonnegative_int(schema_version) is None:
            errors.append("source_binding.census_schema_version")
        generated_at = binding.get("census_generated_at")
        if generated_at is not None and not isinstance(generated_at, str):
            errors.append("source_binding.census_generated_at")
        freshness = _freshness({"generated_at": generated_at}, assessed_at)
        if binding.get("census_age_seconds") != freshness["age_seconds"]:
            errors.append("source_binding.census_age_seconds")

        public_binding_keys = {
            "state",
            "reason",
            "raw_public_sha256",
            "receipt_public_sha256",
            "collection_id",
            "receipt_collection_id",
        }
        public_binding = value.get("public_snapshot_binding")
        if not _exact_keys(public_binding, public_binding_keys):
            errors.append("public_snapshot_binding")
            public_binding = {}
        public_state = public_binding.get("state")
        public_reasons = {
            "UNAVAILABLE": PUBLIC_RECEIPT_UNAVAILABLE_REASON,
            "DIVERGENT": PUBLIC_RECEIPT_DIVERGENT_REASON,
            "MEASURED": PUBLIC_RECEIPT_MEASURED_REASON,
        }
        if public_state not in public_reasons:
            errors.append("public_snapshot_binding.state")
            public_state = "DIVERGENT"
        if public_binding.get("reason") != public_reasons[public_state]:
            errors.append("public_snapshot_binding.reason")
        for name in ("raw_public_sha256", "receipt_public_sha256"):
            digest = public_binding.get(name)
            if digest is not None and not _valid_sha256(digest):
                errors.append(f"public_snapshot_binding.{name}")
        for name in ("collection_id", "receipt_collection_id"):
            identity = public_binding.get(name)
            if identity is not None and (
                not isinstance(identity, str)
                or COLLECTION_ID.fullmatch(identity) is None
            ):
                errors.append(f"public_snapshot_binding.{name}")
        if public_state == "MEASURED" and (
            not _valid_sha256(public_binding.get("raw_public_sha256"))
            or public_binding.get("raw_public_sha256")
            != public_binding.get("receipt_public_sha256")
            or not isinstance(public_binding.get("collection_id"), str)
            or COLLECTION_ID.fullmatch(public_binding["collection_id"]) is None
            or public_binding.get("collection_id")
            != public_binding.get("receipt_collection_id")
        ):
            errors.append("public_snapshot_binding.measured_claim")
        if public_state == "UNAVAILABLE" and (
            public_binding.get("receipt_public_sha256") is not None
            or public_binding.get("collection_id") is not None
            or public_binding.get("receipt_collection_id") is not None
        ):
            errors.append("public_snapshot_binding.unavailable_claim")

        source_states: dict[str, str] = {}
        sources = value.get("sources")
        if not isinstance(sources, Mapping):
            errors.append("sources")
            sources = {}
        else:
            divergent_errors = {
                "Source wrapper is malformed.",
                "Successful source has no object-shaped data.",
            }
            for name, source in sources.items():
                source_valid = (
                    isinstance(name, str)
                    and SOURCE_NAME.fullmatch(name) is not None
                    and _exact_keys(source, {"state", "error"})
                )
                if not source_valid:
                    errors.append(f"sources.{name}")
                    continue
                source_state = source.get("state")
                source_error = source.get("error")
                valid_pair = (
                    (source_state == "MEASURED" and source_error is None)
                    or (
                        source_state == "UNAVAILABLE"
                        and source_error
                        == "Source collection failed; inspect the protected collector log."
                    )
                    or (
                        source_state == "DIVERGENT" and source_error in divergent_errors
                    )
                )
                if not valid_pair:
                    errors.append(f"sources.{name}")
                else:
                    source_states[name] = source_state

        requirements = value.get("requirements")
        if (
            not isinstance(requirements, Mapping)
            or set(requirements) != REQUIRED_REQUIREMENTS
            or any(not _state_reason(item) for item in requirements.values())
        ):
            errors.append("requirements")
            requirements = {}

        inventory = value.get("inventory")
        if not _exact_keys(inventory, {"github", "huggingface"}):
            errors.append("inventory")
            inventory = {}
        github = inventory.get("github", {})
        huggingface = inventory.get("huggingface", {})

        github_keys = {
            "state",
            "release_gate",
            "repository_count",
            "active_count",
            "archived_count",
            "ci",
            "blocked_repositories",
            "unprotected_repositories",
            "protection_unknown_repositories",
            "unclassified_repositories",
            "reason",
        }
        if not _state_reason(github, extra=github_keys - {"state", "reason"}):
            errors.append("inventory.github")
            github = {}
        else:
            github_state = github.get("state")
            if github_state not in {"MEASURED", "UNAVAILABLE", "DIVERGENT"}:
                errors.append("inventory.github.state")
            counts_values = [
                github.get("repository_count"),
                github.get("active_count"),
                github.get("archived_count"),
            ]
            if any(not _nullable_count(item) for item in counts_values):
                errors.append("inventory.github.counts")
            ci = github.get("ci")
            ci_keys = ("success", "failure", "pending", "unknown")
            if not _exact_keys(ci, set(ci_keys)) or any(
                not _nullable_count(ci.get(key)) for key in ci_keys
            ):
                errors.append("inventory.github.ci")
                ci = {}
            github_lists = (
                "blocked_repositories",
                "unprotected_repositories",
                "protection_unknown_repositories",
                "unclassified_repositories",
            )
            for key in github_lists:
                values = github.get(key)
                if not _sorted_unique_strings(values) or any(
                    GITHUB_REPOSITORY.fullmatch(item) is None
                    for item in values
                    if isinstance(item, str)
                ):
                    errors.append(f"inventory.github.{key}")
            total = github.get("repository_count")
            active = github.get("active_count")
            archived = github.get("archived_count")
            counts_are_measured = all(
                type(item) is int for item in (total, active, archived)
            )
            if github_state == "MEASURED" and counts_are_measured:
                if total != active + archived:
                    errors.append("inventory.github.counts")
            elif github_state == "MEASURED" or any(
                item is not None for item in (total, active, archived)
            ):
                errors.append("inventory.github.counts")
            ci_is_measured = all(type(ci.get(key)) is int for key in ci_keys)
            if github_state == "MEASURED" and ci_is_measured:
                if type(active) is int and sum(ci[key] for key in ci_keys) != active:
                    errors.append("inventory.github.ci")
                expected_blocked_count = ci["failure"] + ci["pending"] + ci["unknown"]
                if (
                    len(github.get("blocked_repositories", []))
                    != expected_blocked_count
                ):
                    errors.append("inventory.github.blocked_repositories")
            elif github_state == "MEASURED" or any(
                ci.get(key) is not None for key in ci_keys
            ):
                errors.append("inventory.github.ci")
            if github_state == "MEASURED":
                expected_github_gate = (
                    "BLOCKED"
                    if any(github.get(key) for key in github_lists)
                    else "MEASURED"
                )
                if (
                    github.get("reason")
                    != "GitHub inventory was recomputed from repository evidence."
                ):
                    errors.append("inventory.github.reason")
            else:
                expected_github_gate = github_state
                allowed_reasons = {
                    "GitHub inventory is unavailable.",
                    "GitHub inventory structure is malformed.",
                    "GitHub repository entry is malformed.",
                    "GitHub repository evidence is malformed.",
                    "Branch-protection evidence is malformed.",
                    "Repository classification is malformed.",
                    "Archived repository classification disagrees with lifecycle state.",
                    "Active repository is classified as an archive.",
                    "Repository lifecycle and CI state disagree.",
                    "GitHub discovery did not prove complete organization coverage.",
                }
                reason = github.get("reason")
                if not isinstance(reason, str) or not (
                    reason in allowed_reasons
                    or reason.startswith(
                        "GitHub summary disagrees with repository evidence:"
                    )
                ):
                    errors.append("inventory.github.reason")
            if github.get("release_gate") != expected_github_gate:
                errors.append("inventory.github.release_gate")

        hf_list_keys = (
            "public_space_ids",
            "invalid_asset_ids",
            "duplicate_asset_ids",
            "invalid_revision_ids",
            "missing_license_ids",
            "visibility_unknown_ids",
            "running_unbound_spaces",
            "non_running_dynamic_spaces",
        )
        hf_keys = {
            "state",
            "release_gate",
            "counts",
            "subinventory_states",
            "public_space_count",
            "reason",
            *hf_list_keys,
        }
        if not _state_reason(huggingface, extra=hf_keys - {"state", "reason"}):
            errors.append("inventory.huggingface")
            huggingface = {}
        else:
            hf_state = huggingface.get("state")
            counts = huggingface.get("counts")
            substates = huggingface.get("subinventory_states")
            if not _exact_keys(counts, set(REQUIRED_ASSET_KINDS)) or any(
                not _nullable_count(counts.get(kind)) for kind in REQUIRED_ASSET_KINDS
            ):
                errors.append("inventory.huggingface.counts")
                counts = {}
            if not _exact_keys(substates, set(REQUIRED_ASSET_KINDS)) or any(
                substates.get(kind) not in {"MEASURED", "UNAVAILABLE", "DIVERGENT"}
                for kind in REQUIRED_ASSET_KINDS
            ):
                errors.append("inventory.huggingface.subinventory_states")
                substates = {kind: "DIVERGENT" for kind in REQUIRED_ASSET_KINDS}
            expected_hf_state = (
                "DIVERGENT"
                if "DIVERGENT" in substates.values()
                else "UNAVAILABLE"
                if "UNAVAILABLE" in substates.values()
                else "MEASURED"
            )
            if hf_state != expected_hf_state:
                errors.append("inventory.huggingface.state")
            for kind in REQUIRED_ASSET_KINDS:
                kind_state = substates.get(kind)
                count = counts.get(kind)
                if (kind_state == "MEASURED" and type(count) is not int) or (
                    kind_state in {"UNAVAILABLE", "DIVERGENT"} and count is not None
                ):
                    errors.append(f"inventory.huggingface.counts.{kind}")
            for key in hf_list_keys:
                values = huggingface.get(key)
                if not _sorted_unique_strings(values):
                    errors.append(f"inventory.huggingface.{key}")
            public_ids = huggingface.get("public_space_ids")
            if isinstance(public_ids, list) and any(
                not isinstance(item, str) or HF_ID.fullmatch(item) is None
                for item in public_ids
            ):
                errors.append("inventory.huggingface.public_space_ids")
            public_count = huggingface.get("public_space_count")
            if not _nullable_count(public_count):
                errors.append("inventory.huggingface.public_space_count")
            if type(public_count) is int and isinstance(public_ids, list):
                if public_count != len(public_ids):
                    errors.append("inventory.huggingface.public_space_count")
            if huggingface.get("visibility_unknown_ids") and public_count is not None:
                errors.append("inventory.huggingface.public_space_count")
            if (
                substates.get("spaces") == "MEASURED"
                and not huggingface.get("visibility_unknown_ids")
                and type(public_count) is not int
            ):
                errors.append("inventory.huggingface.public_space_count")
            if substates.get("spaces") != "MEASURED" and (
                public_count is not None or public_ids != []
            ):
                errors.append("inventory.huggingface.public_space_evidence")
            divergence_lists = (
                "invalid_asset_ids",
                "duplicate_asset_ids",
                "invalid_revision_ids",
                "visibility_unknown_ids",
            )
            if any(huggingface.get(key) for key in divergence_lists):
                if expected_hf_state != "DIVERGENT":
                    errors.append("inventory.huggingface.divergence")
            if expected_hf_state == "MEASURED":
                expected_hf_gate = (
                    "BLOCKED"
                    if any(
                        huggingface.get(key)
                        for key in (
                            "missing_license_ids",
                            "running_unbound_spaces",
                            "non_running_dynamic_spaces",
                        )
                    )
                    else "MEASURED"
                )
            else:
                expected_hf_gate = expected_hf_state
            if huggingface.get("release_gate") != expected_hf_gate:
                errors.append("inventory.huggingface.release_gate")
            allowed_hf_reasons = {
                "Hugging Face inventory is unavailable.",
                "Hugging Face asset inventory is malformed.",
                "Hugging Face public projection is a public subset, not a complete organization inventory.",
                "Hugging Face public projection conflicts with a complete-organization claim.",
                "Hugging Face organization completeness is unverified.",
                "Hugging Face counts, identity, visibility, and runtime evidence "
                "were recomputed from asset items.",
            }
            if huggingface.get("reason") not in allowed_hf_reasons:
                errors.append("inventory.huggingface.reason")

        for name, observed, fallback in (
            (
                "github",
                github,
                lambda state: _github_inventory({}, state),
            ),
            (
                "huggingface",
                huggingface,
                lambda state: _hf_inventory({}, state)[0],
            ),
        ):
            source_state = source_states.get(name, "UNAVAILABLE")
            if source_state != "MEASURED" and observed != fallback(source_state):
                errors.append(f"inventory.{name}.source_binding")

        locked_roles = [
            {"domain": domain, "role": role, "source": source}
            for domain, role, source in LOCKED_DOMAIN_ROLES
        ]
        expected_roles = {
            "state": "UNAVAILABLE",
            "targets": locked_roles if policy_state == "MEASURED" else [],
            "reason": PRODUCT_PROOF_REASON,
        }
        if value.get("product_proof_roles") != expected_roles:
            errors.append("product_proof_roles")

        expected_policy = _public_space_policy(
            huggingface,
            policy_state,
            LOCKED_POLICY if policy_state == "MEASURED" else {},
            assessed_at,
        )
        if value.get("public_space_policy") != expected_policy:
            errors.append("public_space_policy")

        benchmark = value.get("governed_agent_bench")
        if not _state_reason(benchmark, extra={"dataset", "space"}):
            errors.append("governed_agent_bench")
            benchmark = {}
        dataset = benchmark.get("dataset")
        space = benchmark.get("space")
        if dataset is not None and not _benchmark_dataset_shape(dataset):
            errors.append("governed_agent_bench.dataset")
            dataset = None
        if space is not None and not _benchmark_space_shape(space):
            errors.append("governed_agent_bench.space")
            space = None
        expected_benchmark = _benchmark_from_summaries(
            dataset,
            space,
            huggingface.get("subinventory_states", {}).get("datasets", "DIVERGENT"),
            huggingface.get("subinventory_states", {}).get("spaces", "DIVERGENT"),
        )
        if benchmark != expected_benchmark:
            errors.append("governed_agent_bench")

        fixed_components = {
            "governed_mcp": {
                "state": "UNAVAILABLE",
                "observed_flagship_endpoints": None,
                "reason": GOVERNED_MCP_REASON,
            },
            "model_promotion": {
                "state": "UNAVAILABLE",
                "reason": MODEL_PROMOTION_REASON,
            },
            "route_tab_inventory": {
                "state": "UNAVAILABLE",
                "routes": None,
                "tabs": None,
                "reason": ROUTE_TABS_REASON,
            },
            "space_cost_posture": {
                "state": "UNAVAILABLE",
                "spaces_with_cost_evidence": None,
                "reason": COST_POSTURE_REASON,
            },
        }
        for name, expected in fixed_components.items():
            if value.get(name) != expected:
                errors.append(name)

        governance_evidence = value.get("governance_evidence")
        if not isinstance(
            governance_evidence, Mapping
        ) or not _governance_evidence_valid(governance_evidence):
            errors.append("governance_evidence")
            governance_evidence = _blank_governance_evidence("DIVERGENT")
        (
            expected_corrections,
            expected_overclaims,
            governance_state,
            governance_reason,
        ) = _ledgers_from_governance_evidence(governance_evidence)
        corrections = value.get("correction_ledger")
        overclaims = value.get("overclaim_ledger")
        if not _validate_ledger(corrections) or corrections != expected_corrections:
            errors.append("correction_ledger")
            corrections = expected_corrections
        if not _validate_ledger(overclaims) or overclaims != expected_overclaims:
            errors.append("overclaim_ledger")
            overclaims = expected_overclaims

        summary = value.get("summary")
        expected_summary = {
            "github_repositories": github.get("repository_count"),
            "github_active_repositories": github.get("active_count"),
            "github_ci_failures": (
                github.get("ci", {}).get("failure")
                if isinstance(github.get("ci"), Mapping)
                else None
            ),
            "hf_models": (
                huggingface.get("counts", {}).get("models")
                if isinstance(huggingface.get("counts"), Mapping)
                else None
            ),
            "hf_datasets": (
                huggingface.get("counts", {}).get("datasets")
                if isinstance(huggingface.get("counts"), Mapping)
                else None
            ),
            "hf_spaces": (
                huggingface.get("counts", {}).get("spaces")
                if isinstance(huggingface.get("counts"), Mapping)
                else None
            ),
            "hf_public_spaces": huggingface.get("public_space_count"),
            "open_corrections": (
                len(corrections.get("entries", []))
                if corrections.get("state") in {"MEASURED", "BLOCKED"}
                else None
            ),
            "open_overclaims": (
                len(overclaims.get("entries", []))
                if overclaims.get("entries") or overclaims.get("state") == "MEASURED"
                else None
            ),
        }
        if (
            not _exact_keys(summary, SUMMARY_KEYS)
            or any(not _nullable_count(item) for item in summary.values())
            or dict(summary) != expected_summary
        ):
            errors.append("summary")

        policy_reason = {
            "MEASURED": POLICY_MEASURED_REASON,
            "UNAVAILABLE": POLICY_UNAVAILABLE_REASON,
            "DIVERGENT": POLICY_DIVERGENT_REASON,
        }[policy_state]
        expected_requirements = {
            "census_schema": {
                "state": (
                    "MEASURED"
                    if schema_version == REPORT_SCHEMA_VERSION
                    else "DIVERGENT"
                ),
                "reason": "Schema-v2 census is required.",
            },
            "compiler_source": {
                "state": expected_source_state,
                "reason": source_reason,
            },
            "correction_and_overclaim_ledger": {
                "state": governance_state,
                "reason": governance_reason,
            },
            "governed_agent_bench": {
                "state": expected_benchmark["state"],
                "reason": expected_benchmark["reason"],
            },
            "governed_mcp": {
                "state": "UNAVAILABLE",
                "reason": GOVERNED_MCP_REASON,
            },
            "github_inventory": {
                "state": github.get("state"),
                "reason": github.get("reason"),
            },
            "github_release_gate": {
                "state": github.get("release_gate"),
                "reason": github.get("reason"),
            },
            "hf_inventory": {
                "state": huggingface.get("state"),
                "reason": huggingface.get("reason"),
            },
            "hf_release_gate": {
                "state": huggingface.get("release_gate"),
                "reason": huggingface.get("reason"),
            },
            "model_promotion": {
                "state": "UNAVAILABLE",
                "reason": MODEL_PROMOTION_REASON,
            },
            "product_proof_roles": {
                "state": "UNAVAILABLE",
                "reason": PRODUCT_PROOF_REASON,
            },
            "public_space_policy": {
                "state": expected_policy["state"],
                "reason": expected_policy["reason"],
            },
            "public_snapshot_receipt": {
                "state": public_state,
                "reason": public_reasons[public_state],
            },
            "route_tab_inventory": {
                "state": "UNAVAILABLE",
                "reason": ROUTE_TABS_REASON,
            },
            "snapshot_freshness": {
                "state": freshness["state"],
                "reason": freshness["reason"],
            },
            "space_cost_posture": {
                "state": "UNAVAILABLE",
                "reason": COST_POSTURE_REASON,
            },
            "target_policy": {
                "state": policy_state,
                "reason": policy_reason,
            },
            **{
                name: {"state": "UNAVAILABLE", "reason": reason}
                for name, reason in FIXED_UNAVAILABLE_REQUIREMENTS.items()
            },
        }
        expected_requirements = dict(sorted(expected_requirements.items()))
        if dict(requirements) != expected_requirements:
            errors.append("requirements_binding")
        if value.get("state") != _overall_state(expected_requirements):
            errors.append("aggregate_state")
        expected_gaps = [
            {
                "requirement": name,
                "state": item["state"],
                "reason": item["reason"],
            }
            for name, item in expected_requirements.items()
            if item["state"] != "MEASURED"
        ]
        if value.get("gaps") != expected_gaps:
            errors.append("gaps")

        digest = value.get("digest_sha256")
        if not isinstance(digest, str) or SHA64.fullmatch(digest) is None:
            errors.append("digest_sha256")
        else:
            unsigned = dict(value)
            unsigned.pop("digest_sha256", None)
            if digest != hashlib.sha256(canonical_bytes(unsigned)).hexdigest():
                errors.append("digest_mismatch")
    except (
        DiligenceError,
        TypeError,
        ValueError,
        RecursionError,
        OverflowError,
        KeyError,
        AttributeError,
    ) as exc:
        errors.append(f"validation:{type(exc).__name__}")
    return sorted(set(errors))


def _md(value: Any) -> str:
    if value is None:
        return "UNAVAILABLE"
    return str(value).replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def render_markdown(artifact: Mapping[str, Any]) -> str:
    errors = validate_artifact(artifact)
    if errors:
        raise DiligenceError(f"cannot render invalid artifact: {', '.join(errors)}")
    summary = artifact["summary"]
    lines = [
        "# SZL Series-A Diligence — Generated",
        "",
        f"- State: **{_md(artifact['state'])}**",
        f"- Assessed at: `{_md(artifact['assessed_at'])}`",
        f"- Compiler revision: `{_md(artifact['source_binding']['compiler_revision'])}`",
        f"- Census SHA-256: `{_md(artifact['source_binding']['census_sha256'])}`",
        f"- Artifact SHA-256: `{_md(artifact['digest_sha256'])}`",
        "- Claim boundary: " + _md(artifact["claim_boundary"]),
        "",
        "## Estate summary",
        "",
        f"- GitHub repositories: {_md(summary['github_repositories'])}",
        f"- Active repositories: {_md(summary['github_active_repositories'])}",
        f"- CI failures: {_md(summary['github_ci_failures'])}",
        f"- Hugging Face models: {_md(summary['hf_models'])}",
        f"- Hugging Face datasets: {_md(summary['hf_datasets'])}",
        f"- Hugging Face Spaces: {_md(summary['hf_spaces'])}",
        f"- Public Spaces: {_md(summary['hf_public_spaces'])}",
        f"- Open corrections: {_md(summary['open_corrections'])}",
        f"- Open overclaim boundaries: {_md(summary['open_overclaims'])}",
        "",
        "## Release requirements",
        "",
        "| Requirement | State | Evidence boundary |",
        "|---|---:|---|",
    ]
    for name, item in artifact["requirements"].items():
        lines.append(
            f"| `{_md(name)}` | **{_md(item['state'])}** | {_md(item['reason'])} |"
        )
    policy = artifact["public_space_policy"]
    lines.extend(
        [
            "",
            "## Public Space policy",
            "",
            f"- State: **{_md(policy['state'])}**",
            f"- Normal limit: {_md(policy['normal_limit'])}",
            f"- Authorized maximum with dated exceptions: {_md(policy['authorized_maximum'])}",
            f"- Observed public Spaces: {_md(policy['public_space_count'])}",
            f"- Boundary: {_md(policy['reason'])}",
            "",
            "## Governed-agent-bench",
            "",
            f"- State: **{_md(artifact['governed_agent_bench']['state'])}**",
            f"- Boundary: {_md(artifact['governed_agent_bench']['reason'])}",
            "",
            "## Corrections",
            "",
        ]
    )
    if artifact["correction_ledger"]["entries"]:
        for item in artifact["correction_ledger"]["entries"]:
            lines.append(
                f"- `{_md(item['id'])}` ({_md(item['severity'])}): {_md(item['summary'])}"
            )
    elif artifact["correction_ledger"]["state"] != "MEASURED":
        lines.append(
            f"- **{_md(artifact['correction_ledger']['state'])}**: "
            f"{_md(artifact['correction_ledger']['reason'])}"
        )
    else:
        lines.append("- No FAIL controls were observed in the supplied census.")
    lines.extend(["", "## Overclaim boundaries", ""])
    if artifact["overclaim_ledger"]["entries"]:
        for item in artifact["overclaim_ledger"]["entries"]:
            lines.append(
                f"- `{_md(item['id'])}` ({_md(item['severity'])}): {_md(item['summary'])}"
            )
    elif artifact["overclaim_ledger"]["state"] != "MEASURED":
        lines.append(
            f"- **{_md(artifact['overclaim_ledger']['state'])}**: "
            f"{_md(artifact['overclaim_ledger']['reason'])}"
        )
    else:
        lines.append("- No UNKNOWN controls were observed in the supplied census.")
    lines.extend(["", "## Explicit gaps", ""])
    if artifact["gaps"]:
        for item in artifact["gaps"]:
            lines.append(
                f"- `{_md(item['requirement'])}` — **{_md(item['state'])}**: {_md(item['reason'])}"
            )
    else:
        lines.append("- None in the supplied evidence boundary.")
    return "\n".join(lines) + "\n"
