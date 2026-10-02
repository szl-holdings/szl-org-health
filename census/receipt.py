"""Build a fail-closed, source-bound receipt for one estate census snapshot."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import sys
import tempfile
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from census.governance import evaluate_report
except ModuleNotFoundError:  # direct isolated execution from census/receipt.py
    governance_path = Path(__file__).with_name("governance.py")
    governance_spec = importlib.util.spec_from_file_location(
        "szl_receipt_governance", governance_path
    )
    if governance_spec is None or governance_spec.loader is None:
        raise RuntimeError("governance evaluator module could not be loaded")
    governance_module = importlib.util.module_from_spec(governance_spec)
    governance_spec.loader.exec_module(governance_module)
    evaluate_report = governance_module.evaluate_report

RECEIPT_SCHEMA = "szl.estate-census-receipt/v1"
GOVERNANCE_SCHEMA = "szl.estate-governance-evaluation/v1"
GOVERNANCE_POLICY_VERSION = "2026-08-11"
SNAPSHOT_SCHEMA_VERSION = 2
HUGGINGFACE_ORGANIZATION = "SZLHOLDINGS"
HUGGINGFACE_AUTHENTICATION_SCHEMA = "szl.hf-authentication-evidence/v2"
HUGGINGFACE_SCOPE_STATES = {
    "UNAVAILABLE",
    "IDENTITY_ONLY",
    "IDENTITY_AND_ORG_ROLE_OBSERVED",
    "AUTHENTICATED_BOUNDED",
    "ORG_COMPLETE",
}
HUGGINGFACE_PROBE_STATES = {
    "UNAVAILABLE",
    "CREDENTIAL_NOT_CONFIGURED",
    "INVALID_CREDENTIAL",
    "DENIED_OR_RESTRICTED",
    "RATE_LIMITED",
    "REQUEST_FAILED",
    "INVALID_RESPONSE",
    "AUTHENTICATED",
}
HUGGINGFACE_CREDENTIAL_CLASSES = {
    "FINE_GRAINED",
    "LEGACY_READ",
    "LEGACY_WRITE",
    "UNKNOWN",
}
REQUIRED_SOURCES = ("github", "huggingface", "sites", "dns")
GOVERNANCE_STATUSES = ("PASS", "FAIL", "UNKNOWN", "NOT_APPLICABLE")
REQUIRED_GOVERNANCE_CONTROL_IDS = (
    "GH-INVENTORY",
    "GH-ACTIVE-CI",
    "GH-BRANCH-PROTECTION",
    "GH-HIGH-CODE-ALERTS",
    "GH-SECRET-ALERTS",
    "GH-DEPENDABOT-ALERTS",
    "GH-REPOSITORY-CLASSIFICATION",
    "HF-INVENTORY",
    "HF-CARDS",
    "HF-LICENSES",
    "HF-SAFE-MODEL-FORMATS",
    "HF-IMMUTABLE-REVISIONS",
    "HF-DYNAMIC-SPACE-SOURCE-BINDING",
    "DNS-SPF",
    "DNS-DMARC-REJECT",
)
SHA40 = re.compile(r"^[0-9a-f]{40}$")
REPOSITORY_NAME = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
POSITIVE_DECIMAL = re.compile(r"^[1-9][0-9]*$")
MAX_SNAPSHOT_AGE_SECONDS = 30 * 60
MAX_FUTURE_SKEW_SECONDS = 5 * 60
DEFAULT_SNAPSHOT = Path("census-internal.json")
DEFAULT_RECEIPT = Path("census-receipt.json")
SUBJECT_FIELDS = (
    "repository",
    "workflow_sha",
    "run_id",
    "run_attempt",
    "run_url",
)


def parse_utc_timestamp(value: Any) -> datetime | None:
    """Parse an aware ISO-8601 timestamp and normalize it to UTC."""
    if not isinstance(value, str) or not value:
        return None
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed.astimezone(timezone.utc)


def _safe_governance_status(value: Any) -> str | None:
    return value if value in GOVERNANCE_STATUSES else None


def _governance_status_label(value: Any) -> str:
    """Describe a status without reflecting untrusted snapshot content."""
    return _safe_governance_status(value) or ("MISSING" if value is None else "INVALID")


def _safe_governance_summary(value: Any) -> dict[str, int | None] | None:
    if not isinstance(value, dict):
        return None
    projected: dict[str, int | None] = {}
    for status in GOVERNANCE_STATUSES:
        count = value.get(status)
        projected[status] = (
            count
            if isinstance(count, int) and not isinstance(count, bool) and count >= 0
            else None
        )
    return projected


def _safe_timestamp(value: Any) -> str | None:
    parsed = parse_utc_timestamp(value)
    return parsed.isoformat().replace("+00:00", "Z") if parsed is not None else None


def load_snapshot(path: Path) -> tuple[bytes | None, str | None]:
    """Read exact snapshot bytes without persisting path-bearing diagnostics."""
    try:
        return path.read_bytes(), None
    except FileNotFoundError:
        return None, "NOT_FOUND"
    except OSError:
        return None, "READ_FAILED"


def _json_object(snapshot_bytes: bytes | None) -> tuple[dict[str, Any], str | None]:
    if snapshot_bytes is None:
        return {}, None
    try:
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate field")
                result[key] = value
            return result

        loaded = json.loads(snapshot_bytes, object_pairs_hook=unique)
        json.dumps(loaded, allow_nan=False).encode("utf-8")
    except (UnicodeError, ValueError, RecursionError):
        return {}, "INVALID_JSON"
    if not isinstance(loaded, dict):
        return {}, "INVALID_ROOT"
    return loaded, None


def validate_collection(snapshot: Mapping[str, Any], subject: Mapping[str, Any]) -> bool:
    """Bind measurement windows, exact sources and the collecting run attempt.

    This is consistency evidence, not a signature or an organization-completeness
    claim. A timestamp rewritten on a retained fallback cannot satisfy it.
    """
    collection = snapshot.get("collection")
    if not isinstance(collection, dict) or collection.get("schema") != "szl.census-collection/v1":
        return False
    identity = collection.get("id")
    if not isinstance(identity, str) or not re.fullmatch(r"[0-9a-f]{32}", identity):
        return False
    collected_subject = collection.get("subject")
    if not isinstance(collected_subject, dict) or any(
        collected_subject.get(key) != subject.get(key) or subject.get(key) is None
        for key in ("repository", "workflow_sha", "run_id", "run_attempt")
    ):
        return False
    started = parse_utc_timestamp(collection.get("started_at"))
    completed = parse_utc_timestamp(collection.get("completed_at"))
    generated = parse_utc_timestamp(snapshot.get("generated_at"))
    if (started is None or completed is None or generated != completed
            or not 0 <= (completed - started).total_seconds() <= MAX_SNAPSHOT_AGE_SECONDS):
        return False
    observations = collection.get("source_observations")
    sources = snapshot.get("sources")
    if not isinstance(observations, dict) or set(observations) != set(REQUIRED_SOURCES):
        return False
    if not isinstance(sources, dict) or set(sources) != set(REQUIRED_SOURCES):
        return False
    for value in observations.values():
        if not isinstance(value, dict):
            return False
        begin = parse_utc_timestamp(value.get("started_at"))
        end = parse_utc_timestamp(value.get("completed_at"))
        if begin is None or end is None or not started <= begin <= end <= completed:
            return False
    encoded = (json.dumps(sources, separators=(",", ":"), sort_keys=True, allow_nan=False) + "\n").encode("utf-8")
    return collection.get("sources_sha256") == hashlib.sha256(encoded).hexdigest()


def stage_public_snapshot(snapshot_bytes: bytes | None, public_path: Path,
                          destination: Path, receipt: Mapping[str, Any]) -> dict[str, Any]:
    """Only stage the exact projection produced by this collection for upload."""
    result = {"state": "WITHHELD", "sha256": None, "collection_id": None}
    # Never carry an artifact candidate left by an earlier invocation into a new run.
    destination.unlink(missing_ok=True)
    observations = receipt.get("observations", {})
    if (receipt.get("collector_outcome") != "success"
            or observations.get("collection_binding_matches") is not True
            or observations.get("snapshot_freshness_valid") is not True):
        return result
    snapshot, error = _json_object(snapshot_bytes)
    if error or snapshot_bytes is None:
        return result
    staged: Path | None = None
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        from census.report import project_public_report, serialize_report
        expected = serialize_report(project_public_report(snapshot)).encode("utf-8")
        if public_path.read_bytes() != expected:
            return result
        with tempfile.NamedTemporaryFile(mode="wb", dir=destination.parent,
                prefix=".census-public-", suffix=".tmp", delete=False) as handle:
            staged = Path(handle.name)
            handle.write(expected)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(staged, destination)
        staged = None
    except (OSError, ValueError, TypeError, RecursionError):
        return result
    finally:
        if staged is not None:
            staged.unlink(missing_ok=True)
    return {"state": "FRESH_COLLECTION_BOUND", "sha256": hashlib.sha256(expected).hexdigest(),
            "collection_id": snapshot["collection"]["id"]}


def _subject_projection(subject: Mapping[str, str | None]) -> dict[str, str | None]:
    projected: dict[str, str | None] = {}
    for field in SUBJECT_FIELDS:
        value = subject.get(field)
        projected[field] = value if isinstance(value, str) or value is None else None
    return projected


def _validate_subject(
    subject: Mapping[str, str | None],
) -> tuple[dict[str, str | None], bool, list[str]]:
    projected = _subject_projection(subject)
    errors: list[str] = []
    repository = projected["repository"]
    workflow_sha = projected["workflow_sha"]
    run_id = projected["run_id"]
    run_attempt = projected["run_attempt"]
    run_url = projected["run_url"]

    if not isinstance(repository, str) or not REPOSITORY_NAME.fullmatch(repository):
        errors.append("receipt subject repository is missing or invalid")
    if not isinstance(workflow_sha, str) or not SHA40.fullmatch(workflow_sha):
        errors.append("receipt subject workflow_sha is missing or invalid")
    if not isinstance(run_id, str) or not POSITIVE_DECIMAL.fullmatch(run_id):
        errors.append("receipt subject run_id is missing or invalid")
    if not isinstance(run_attempt, str) or not POSITIVE_DECIMAL.fullmatch(run_attempt):
        errors.append("receipt subject run_attempt is missing or invalid")
    expected_url = (
        f"https://github.com/{repository}/actions/runs/{run_id}"
        if isinstance(repository, str)
        and REPOSITORY_NAME.fullmatch(repository)
        and isinstance(run_id, str)
        and POSITIVE_DECIMAL.fullmatch(run_id)
        else None
    )
    if not isinstance(run_url, str) or run_url != expected_url:
        errors.append("receipt subject run_url is missing, invalid, or inconsistent")
    safe_projection = {
        "repository": repository
        if isinstance(repository, str) and REPOSITORY_NAME.fullmatch(repository)
        else None,
        "workflow_sha": workflow_sha
        if isinstance(workflow_sha, str) and SHA40.fullmatch(workflow_sha)
        else None,
        "run_id": run_id
        if isinstance(run_id, str) and POSITIVE_DECIMAL.fullmatch(run_id)
        else None,
        "run_attempt": run_attempt
        if isinstance(run_attempt, str) and POSITIVE_DECIMAL.fullmatch(run_attempt)
        else None,
        "run_url": run_url
        if isinstance(run_url, str) and run_url == expected_url
        else None,
    }
    return safe_projection, not errors, errors


def _validate_governance(governance: Any) -> tuple[bool, list[str]]:
    errors: list[str] = []
    if not isinstance(governance, dict):
        return False, ["governance evaluation object is missing or invalid"]

    if governance.get("schema") != GOVERNANCE_SCHEMA:
        errors.append("governance evaluation schema is missing or unsupported")
    if governance.get("policy_status") != "TARGET":
        errors.append("governance policy_status is not TARGET")
    if governance.get("policy_version") != GOVERNANCE_POLICY_VERSION:
        errors.append("governance policy_version does not match the receipt contract")
    if governance.get("certification") != "NOT_A_CERTIFICATION":
        errors.append("governance certification boundary is missing or invalid")

    operating_model = governance.get("operating_model")
    operating_model_valid = (
        isinstance(operating_model, dict)
        and operating_model.get("type") == "solo-maintainer"
        and operating_model.get("dco_required") is False
        and operating_model.get("independent_human_review_required") is False
        and operating_model.get(
            "independent_review_claim_allowed_without_external_actor"
        )
        is False
    )
    if not operating_model_valid:
        errors.append(
            "governance solo-maintainer operating model is missing or invalid"
        )

    controls = governance.get("controls")
    observed_ids: list[str] = []
    computed_summary = {status: 0 for status in GOVERNANCE_STATUSES}
    control_shape_valid = isinstance(controls, list) and bool(controls)
    control_details_valid = control_shape_valid
    if isinstance(controls, list):
        for control in controls:
            if not isinstance(control, dict):
                control_shape_valid = False
                control_details_valid = False
                continue
            control_id = control.get("id")
            status = control.get("status")
            if not isinstance(control_id, str) or not control_id:
                control_shape_valid = False
            else:
                observed_ids.append(control_id)
            if status not in GOVERNANCE_STATUSES:
                control_shape_valid = False
            else:
                computed_summary[status] += 1
            if (
                not isinstance(control.get("summary"), str)
                or not control.get("summary")
                or not isinstance(control.get("evidence"), dict)
                or not control.get("evidence")
                or not isinstance(control.get("severity"), str)
                or not isinstance(control.get("frameworks"), list)
                or not control.get("frameworks")
            ):
                control_details_valid = False
    if not control_shape_valid:
        errors.append("governance controls are missing or structurally invalid")
    if not control_details_valid:
        errors.append("governance control evidence metadata is incomplete")
    if len(observed_ids) != len(set(observed_ids)) or set(observed_ids) != set(
        REQUIRED_GOVERNANCE_CONTROL_IDS
    ):
        errors.append("governance control IDs do not match the governed policy")

    summary = governance.get("summary")
    summary_valid = (
        isinstance(summary, dict)
        and set(summary) == set(GOVERNANCE_STATUSES)
        and all(
            isinstance(summary.get(status), int)
            and not isinstance(summary.get(status), bool)
            and summary.get(status) == computed_summary[status]
            for status in GOVERNANCE_STATUSES
        )
    )
    if not summary_valid:
        errors.append("governance summary is missing or inconsistent with controls")

    expected_overall = (
        "FAIL"
        if computed_summary["FAIL"]
        else "UNKNOWN"
        if computed_summary["UNKNOWN"]
        else "PASS"
    )
    if governance.get("overall_status") != expected_overall:
        errors.append("governance overall_status is inconsistent with controls")
    return not errors, errors


def build_receipt(
    snapshot_bytes: bytes | None,
    *,
    snapshot_path: str,
    snapshot_load_error: str | None,
    now: datetime,
    collector_outcome: str | None,
    expected_github_repositories_minimum: int | None,
    credential_presence: Mapping[str, bool],
    subject: Mapping[str, str | None],
    extra_errors: Sequence[str] = (),
) -> dict[str, Any]:
    """Evaluate one exact snapshot without upgrading missing evidence to PASS."""
    errors = (
        ["receipt precondition failed"]
        if any(str(error) for error in extra_errors)
        else []
    )

    if now.tzinfo is None or now.utcoffset() is None:
        errors.append("receipt clock is not timezone-aware")
        now_utc = now.replace(tzinfo=timezone.utc)
    else:
        now_utc = now.astimezone(timezone.utc)

    collector_outcome_state = (
        collector_outcome
        if collector_outcome in {"success", "failure", "cancelled"}
        else "unknown"
    )
    if collector_outcome_state != "success":
        errors.append("collector step did not complete successfully")

    if snapshot_load_error:
        errors.append("snapshot unavailable or invalid: read failed")
    elif snapshot_bytes is None:
        errors.append("snapshot unavailable or invalid: no snapshot bytes")

    snapshot, decode_error = _json_object(snapshot_bytes)
    if decode_error:
        errors.append("snapshot unavailable or invalid: decode failed")

    if snapshot.get("schema_version") != SNAPSHOT_SCHEMA_VERSION:
        errors.append(f"snapshot schema_version is not {SNAPSHOT_SCHEMA_VERSION}")

    generated_at = parse_utc_timestamp(snapshot.get("generated_at"))
    age_seconds: float | None = None
    if generated_at is None:
        errors.append("snapshot generated_at is missing or invalid")
    else:
        raw_age_seconds = (now_utc - generated_at).total_seconds()
        age_seconds = round(raw_age_seconds, 3)
        if (
            raw_age_seconds < -MAX_FUTURE_SKEW_SECONDS
            or raw_age_seconds > MAX_SNAPSHOT_AGE_SECONDS
        ):
            errors.append(
                "snapshot freshness is outside the accepted -300..1800 second window"
            )

    source_states: dict[str, bool] = {}
    sources = snapshot.get("sources")
    if not isinstance(sources, dict):
        sources = {}
        errors.append("snapshot sources object is missing")
    for name in REQUIRED_SOURCES:
        source = sources.get(name)
        source_ok = (
            isinstance(source, dict)
            and source.get("ok") is True
            and isinstance(source.get("data"), dict)
            and bool(source.get("data"))
        )
        source_states[name] = source_ok
        if not source_ok:
            errors.append(f"required source is not complete: {name}")

    governance = snapshot.get("governance")
    governance_status = (
        governance.get("overall_status") if isinstance(governance, dict) else None
    )
    governance_summary = (
        governance.get("summary") if isinstance(governance, dict) else None
    )
    governance_generated_at = (
        governance.get("generated_at_from_census")
        if isinstance(governance, dict)
        else None
    )
    snapshot_generated_at = snapshot.get("generated_at")
    governance_binding_matches = (
        isinstance(snapshot_generated_at, str)
        and governance_generated_at == snapshot_generated_at
    )
    governance_contract_valid, governance_contract_errors = _validate_governance(
        governance
    )
    errors.extend(governance_contract_errors)
    try:
        recomputed_governance = evaluate_report(snapshot)
    except Exception:  # noqa: BLE001 - untrusted snapshot evaluation must fail closed
        recomputed_governance = {}
        errors.append("governance evaluation could not be recomputed from source data")
    recomputed_governance_status = (
        recomputed_governance.get("overall_status")
        if isinstance(recomputed_governance, dict)
        else None
    )
    recomputed_governance_summary = (
        recomputed_governance.get("summary")
        if isinstance(recomputed_governance, dict)
        else None
    )
    governance_recomputed_matches = governance == recomputed_governance
    if not governance_recomputed_matches:
        errors.append("embedded governance does not match source-data recomputation")
    if governance_status != "PASS":
        errors.append(
            "embedded governance overall_status is not PASS: "
            f"{_governance_status_label(governance_status)}"
        )
    if recomputed_governance_status != "PASS":
        errors.append(
            "recomputed governance overall_status is not PASS: "
            f"{_governance_status_label(recomputed_governance_status)}"
        )
    if not governance_binding_matches:
        errors.append("governance evaluation is not bound to snapshot generated_at")

    github_source = sources.get("github")
    github_data = (
        github_source.get("data")
        if isinstance(github_source, dict)
        and isinstance(github_source.get("data"), dict)
        else {}
    )
    discovery = (
        github_data.get("discovery")
        if isinstance(github_data.get("discovery"), dict)
        else {}
    )
    github_summary = (
        github_data.get("summary")
        if isinstance(github_data.get("summary"), dict)
        else {}
    )
    github_total = github_summary.get("total")
    valid_minimum = (
        isinstance(expected_github_repositories_minimum, int)
        and not isinstance(expected_github_repositories_minimum, bool)
        and expected_github_repositories_minimum >= 0
    )
    if not valid_minimum:
        minimum_error = "expected GitHub repository minimum is missing or invalid"
        if minimum_error not in errors:
            errors.append(minimum_error)

    if discovery.get("complete") is not True:
        errors.append("GitHub organization discovery is not complete")
    if discovery.get("scope") != "organization-api":
        errors.append("GitHub discovery scope is not organization-api")
    if valid_minimum:
        if not isinstance(github_total, int) or isinstance(github_total, bool):
            errors.append("observed GitHub repository count is unavailable")
        elif github_total < expected_github_repositories_minimum:
            errors.append(
                "observed GitHub repository count is below the governed minimum "
                f"of {expected_github_repositories_minimum}"
            )
    discovery_projection = {
        "complete": discovery.get("complete") is True,
        "scope": discovery.get("scope")
        if discovery.get("scope") in {"organization-api", "fallback-subset"}
        else "unavailable",
    }

    huggingface_source = sources.get("huggingface")
    huggingface_data = (
        huggingface_source.get("data")
        if isinstance(huggingface_source, dict)
        and isinstance(huggingface_source.get("data"), dict)
        else {}
    )
    raw_huggingface_authentication = (
        huggingface_data.get("authentication")
        if isinstance(huggingface_data.get("authentication"), dict)
        else {}
    )
    raw_scope = raw_huggingface_authentication.get("inventory_scope")
    raw_probe = raw_huggingface_authentication.get("probe_state")
    huggingface_authentication = {
        "schema_valid": raw_huggingface_authentication.get("schema")
        == HUGGINGFACE_AUTHENTICATION_SCHEMA,
        "credential_present": raw_huggingface_authentication.get("credential_present")
        is True,
        "identity_authenticated": raw_huggingface_authentication.get(
            "identity_authenticated"
        )
        is True,
        "user_identity_observed": raw_huggingface_authentication.get(
            "user_identity_observed"
        )
        is True,
        "target_organization_match_observed": (
            raw_huggingface_authentication.get("target_organization")
            == HUGGINGFACE_ORGANIZATION
            and raw_huggingface_authentication.get("target_organization_match_observed")
            is True
        ),
        "organization_membership_observed": raw_huggingface_authentication.get(
            "organization_membership_observed"
        )
        is True,
        "organization_read_role_observed": raw_huggingface_authentication.get(
            "organization_read_role_observed"
        )
        is True,
        "credential_class": (
            raw_huggingface_authentication.get("credential_class")
            if raw_huggingface_authentication.get("credential_class")
            in HUGGINGFACE_CREDENTIAL_CLASSES
            else "UNKNOWN"
        ),
        "fine_grained_metadata_observed": raw_huggingface_authentication.get(
            "fine_grained_metadata_observed"
        )
        is True,
        "org_scope_candidate_observed": raw_huggingface_authentication.get(
            "org_scope_candidate_observed"
        )
        is True,
        "unknown_grants_observed": (
            raw_huggingface_authentication.get("unknown_grants_observed")
            if isinstance(
                raw_huggingface_authentication.get("unknown_grants_observed"), bool
            )
            else None
        ),
        "global_permissions_state": (
            raw_huggingface_authentication.get("global_permissions_state")
            if raw_huggingface_authentication.get("global_permissions_state")
            in {"NONE", "PRESENT", "UNAVAILABLE"}
            else "UNAVAILABLE"
        ),
        "inventory_scope": (
            raw_scope if raw_scope in HUGGINGFACE_SCOPE_STATES else "UNAVAILABLE"
        ),
        "probe_state": (
            raw_probe if raw_probe in HUGGINGFACE_PROBE_STATES else "UNAVAILABLE"
        ),
    }
    if huggingface_authentication.get("schema_valid") is not True:
        errors.append("Hugging Face authentication evidence schema is unavailable")
    if huggingface_authentication.get("credential_present") is not True:
        errors.append("Hugging Face credential presence was not observed")
    if huggingface_authentication.get("identity_authenticated") is not True:
        errors.append("Hugging Face credential identity was not authenticated")
    if huggingface_authentication.get("user_identity_observed") is not True:
        errors.append("Hugging Face user identity was not observed")
    if (
        huggingface_authentication.get("target_organization_match_observed") is not True
        or huggingface_authentication.get("organization_membership_observed")
        is not True
    ):
        errors.append("Hugging Face organization membership was not observed")
    if huggingface_authentication.get("organization_read_role_observed") is not True:
        errors.append("Hugging Face organization read role was not observed")
    if huggingface_authentication.get("probe_state") != "AUTHENTICATED":
        errors.append("Hugging Face identity probe was not authenticated")
    if huggingface_authentication.get("credential_class") != "FINE_GRAINED":
        errors.append("Hugging Face credential was not proven fine-grained")
    if huggingface_authentication.get("fine_grained_metadata_observed") is not True:
        errors.append("Hugging Face fine-grained credential metadata was not observed")
    if huggingface_authentication.get("org_scope_candidate_observed") is not True:
        errors.append("Hugging Face organization-scoped read access was not observed")
    if huggingface_authentication.get("unknown_grants_observed") is not False:
        errors.append("Hugging Face credential grants were incomplete or unrecognized")
    if huggingface_authentication.get("global_permissions_state") != "NONE":
        errors.append(
            "Hugging Face credential global permissions were not proven absent"
        )
    if (
        huggingface_authentication.get("inventory_scope") != "ORG_COMPLETE"
        or raw_huggingface_authentication.get(
            "organization_complete_reconciliation_observed"
        )
        is not True
        or raw_huggingface_authentication.get(
            "organization_complete_reconciliation_method"
        )
        not in {"AUTHORITATIVE_ORG_EXPORT", "ENTERPRISE_ADMIN_API"}
    ):
        errors.append("Hugging Face organization-complete inventory was not proven")

    credentials = {
        "cross_repository_github_read": credential_presence.get(
            "cross_repository_github_read"
        )
        is True,
        "huggingface_token_supplied": credential_presence.get(
            "huggingface_token_supplied"
        )
        is True,
    }
    if not credentials["cross_repository_github_read"]:
        errors.append("cross-repository GitHub read credential is not configured")
    if not credentials["huggingface_token_supplied"]:
        errors.append("Hugging Face credential was not supplied")

    subject_projection, subject_valid, subject_errors = _validate_subject(subject)
    errors.extend(subject_errors)
    collection_binding_matches = subject_valid and validate_collection(snapshot, subject_projection)
    if not collection_binding_matches:
        errors.append("collection windows, source digest or collecting run identity do not match")

    return {
        "schema": RECEIPT_SCHEMA,
        "generated_at": now_utc.isoformat().replace("+00:00", "Z"),
        "status": "PASS" if not errors else "FAIL_CLOSED",
        "subject": subject_projection,
        "collector_outcome": collector_outcome_state,
        "snapshot": {
            "path": Path(snapshot_path).name,
            "sha256": (
                hashlib.sha256(snapshot_bytes).hexdigest()
                if snapshot_bytes is not None
                else None
            ),
            "generated_at": _safe_timestamp(snapshot_generated_at),
            "age_seconds": age_seconds,
            "schema_version": SNAPSHOT_SCHEMA_VERSION
            if snapshot.get("schema_version") == SNAPSHOT_SCHEMA_VERSION
            else None,
        },
        "credential_presence": credentials,
        "observations": {
            "required_sources": source_states,
            "governance_status": _safe_governance_status(governance_status),
            "governance_summary": _safe_governance_summary(governance_summary),
            "governance_generated_at_from_census": _safe_timestamp(
                governance_generated_at
            ),
            "governance_binding_matches": governance_binding_matches,
            "governance_contract_valid": governance_contract_valid,
            "governance_recomputed_status": _safe_governance_status(
                recomputed_governance_status
            ),
            "governance_recomputed_summary": _safe_governance_summary(
                recomputed_governance_summary
            ),
            "governance_recomputed_matches": governance_recomputed_matches,
            "subject_valid": subject_valid,
            "collection_binding_matches": collection_binding_matches,
            "snapshot_freshness_valid": (
                age_seconds is not None
                and -MAX_FUTURE_SKEW_SECONDS <= raw_age_seconds <= MAX_SNAPSHOT_AGE_SECONDS
            ),
            "huggingface_authentication": huggingface_authentication,
            "github_discovery": discovery_projection,
            "github_repository_total": github_total
            if isinstance(github_total, int)
            and not isinstance(github_total, bool)
            and github_total >= 0
            else None,
            "github_repository_minimum": (
                expected_github_repositories_minimum if valid_minimum else None
            ),
        },
        "errors": errors,
    }


def render_summary(receipt: Mapping[str, Any]) -> str:
    """Render a bounded GitHub Actions summary without embedding credentials."""
    snapshot = receipt.get("snapshot")
    observations = receipt.get("observations")
    snapshot = snapshot if isinstance(snapshot, Mapping) else {}
    observations = observations if isinstance(observations, Mapping) else {}
    required_sources = observations.get("required_sources")
    required_sources = required_sources if isinstance(required_sources, Mapping) else {}
    errors = receipt.get("errors")
    error_count = len(errors) if isinstance(errors, list) else 0
    source_failure_count = sum(
        required_sources.get(name) is not True for name in REQUIRED_SOURCES
    )
    return (
        "\n".join(
            [
                "## Scheduled estate census",
                "",
                f"- Status: `{receipt.get('status')}`",
                f"- Snapshot SHA-256: `{snapshot.get('sha256')}`",
                (
                    "- GitHub repositories observed: "
                    f"`{observations.get('github_repository_total')}`"
                ),
                f"- Governance: `{observations.get('governance_status') or 'MISSING'}`",
                f"- Required source failures: `{source_failure_count}`",
                f"- Gate errors: `{error_count}`",
            ]
        )
        + "\n"
    )


def _env_true(environ: Mapping[str, str], name: str) -> bool:
    return environ.get(name, "").strip().lower() == "true"


def _env_nonnegative_int(
    environ: Mapping[str, str], name: str
) -> tuple[int | None, str | None]:
    value = environ.get(name, "").strip()
    try:
        parsed = int(value)
    except ValueError:
        return None, "expected GitHub repository minimum is missing or invalid"
    if parsed < 0:
        return None, "expected GitHub repository minimum is missing or invalid"
    return parsed, None


def main(
    argv: Sequence[str] | None = None,
    environ: Mapping[str, str] | None = None,
    now: datetime | None = None,
) -> int:
    """Write and print a receipt; return zero only for fully passing evidence."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", default=str(DEFAULT_SNAPSHOT))
    parser.add_argument("--receipt", default=str(DEFAULT_RECEIPT))
    parser.add_argument("--public-snapshot")
    parser.add_argument("--publish-snapshot")
    arguments = parser.parse_args(list(argv) if argv is not None else None)
    if bool(arguments.public_snapshot) != bool(arguments.publish_snapshot):
        parser.error("--public-snapshot and --publish-snapshot must be supplied together")

    environment = os.environ if environ is None else environ
    snapshot_path = Path(arguments.snapshot)
    receipt_path = Path(arguments.receipt)
    snapshot_bytes, snapshot_error = load_snapshot(snapshot_path)
    expected_minimum, minimum_error = _env_nonnegative_int(
        environment, "EXPECTED_GITHUB_REPOSITORIES_MINIMUM"
    )
    receipt = build_receipt(
        snapshot_bytes,
        snapshot_path=snapshot_path.as_posix(),
        snapshot_load_error=snapshot_error,
        now=now or datetime.now(timezone.utc),
        collector_outcome=environment.get("COLLECT_OUTCOME"),
        expected_github_repositories_minimum=expected_minimum,
        credential_presence={
            "cross_repository_github_read": _env_true(
                environment, "HAS_CROSS_REPO_GITHUB_TOKEN"
            ),
            "huggingface_token_supplied": _env_true(environment, "HAS_HF_TOKEN"),
        },
        subject={
            "repository": environment.get("RECEIPT_REPOSITORY"),
            "workflow_sha": environment.get("RECEIPT_WORKFLOW_SHA"),
            "run_id": environment.get("RECEIPT_RUN_ID"),
            "run_attempt": environment.get("RECEIPT_RUN_ATTEMPT"),
            "run_url": environment.get("RECEIPT_RUN_URL"),
        },
        extra_errors=([minimum_error] if minimum_error else []),
    )

    if arguments.public_snapshot:
        source_paths = {snapshot_path.resolve(), receipt_path.resolve(), Path(arguments.public_snapshot).resolve()}
        publish_path = Path(arguments.publish_snapshot)
        if publish_path.resolve() in source_paths:
            parser.error("publication destination must be separate from snapshot and receipt inputs")
        receipt["public_snapshot"] = stage_public_snapshot(
            snapshot_bytes, Path(arguments.public_snapshot), publish_path, receipt
        )
        if receipt["public_snapshot"]["state"] != "FRESH_COLLECTION_BOUND":
            receipt["errors"].append("public snapshot withheld: no exact current collection projection")
            receipt["status"] = "FAIL_CLOSED"

    serialized = json.dumps(receipt, indent=2, sort_keys=True) + "\n"
    try:
        receipt_path.write_text(serialized, encoding="utf-8")
    except OSError:
        receipt["errors"].append("receipt could not be written")
        receipt["status"] = "FAIL_CLOSED"

    summary_path = environment.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        try:
            Path(summary_path).write_text(render_summary(receipt), encoding="utf-8")
        except OSError:
            receipt["errors"].append("workflow summary could not be written")
            receipt["status"] = "FAIL_CLOSED"
            try:
                receipt_path.write_text(
                    json.dumps(receipt, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
            except OSError:
                pass

    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0 if receipt["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
