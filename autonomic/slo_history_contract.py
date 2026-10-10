#!/usr/bin/env python3
"""Segment retained SLO history when a declared probe contract changes.

Availability history is meaningful only for one stable monitoring predicate. The
normal path compares the manifest revision retained in the SLO state with current
verified source. A small reviewed registry handles the one safe retroactive case
where an older controller advanced the manifest revision before history migration
existed. Applied retroactive migration IDs live in a separate machine-managed issue
so the ordinary SLO controller cannot erase them while rewriting its own state.

The module mutates issue state only. It cannot restart a service, dispatch a
workflow, modify product source, change DNS, or touch provider state.
"""

from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path
from typing import Any, Mapping, Sequence

from autonomic.slo_controller import (
    ContractError,
    GitHubApi,
    SHA40,
    STATE_BEGIN,
    STATE_END,
    canonical_json,
    encode_state,
    extract_state,
    load_policy,
    load_signed_manifest,
    require,
    sha256_hex,
    utc_now,
    validate_manifest,
    write_json_atomic,
)

MIGRATION_SCHEMA = "szl.autonomic-slo-history-migration/v2"
REGISTRY_SCHEMA = "szl.autonomic-slo-history-migrations/v1"
MARKER_SCHEMA = "szl.autonomic-slo-history-migration-state/v1"
MARKER_TITLE = "[AUTONOMIC-SLO] Applied history migrations"
MARKER_BEGIN = "<!-- SZL_AUTONOMIC_SLO_MIGRATIONS_BEGIN\n"
MARKER_END = "\nSZL_AUTONOMIC_SLO_MIGRATIONS_END -->"
MIGRATION_ID = re.compile(r"^[a-z0-9][a-z0-9-]{2,95}$")


def surface_contract(surface: Mapping[str, Any]) -> dict[str, Any]:
    """Return only fields that define one surface's measured SLO predicate."""
    return {
        "id": surface["id"],
        "hf_repository": surface["hf_repository"],
        "base_url": surface["base_url"],
        # Probe ordering does not change the measured availability predicate.
        "required_paths": sorted(surface["required_paths"]),
        "build_info_path": surface["build_info_path"],
    }


def contract_digest(surface: Mapping[str, Any]) -> str:
    return sha256_hex(canonical_json(surface_contract(surface)))


def contract_map(manifest: Mapping[str, Any]) -> dict[str, str]:
    surfaces = manifest.get("surfaces")
    require(isinstance(surfaces, list), "manifest is missing normalized surfaces")
    result: dict[str, str] = {}
    for surface in surfaces:
        require(isinstance(surface, dict), "manifest surface is invalid")
        identifier = surface.get("id")
        require(isinstance(identifier, str) and identifier, "manifest surface id is invalid")
        require(identifier not in result, "manifest contains duplicate surface ids")
        result[identifier] = contract_digest(surface)
    return result


def empty_surface_history() -> dict[str, Any]:
    return {
        "buckets": [],
        "current_failure_started_at": None,
        "last_ok_at": None,
        "last_provider_blocker": None,
    }


def migrate_history(
    state: Mapping[str, Any],
    previous_manifest: Mapping[str, Any],
    current_manifest: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Reset added/changed predicates and preserve unchanged history exactly."""
    history = state.get("surface_history")
    require(isinstance(history, dict), "persisted SLO history is invalid")
    previous_contracts = contract_map(previous_manifest)
    current_contracts = contract_map(current_manifest)

    changed = sorted(
        identifier
        for identifier in previous_contracts.keys() & current_contracts.keys()
        if previous_contracts[identifier] != current_contracts[identifier]
    )
    added = sorted(current_contracts.keys() - previous_contracts.keys())
    removed = sorted(previous_contracts.keys() - current_contracts.keys())
    unchanged = sorted(
        identifier
        for identifier in previous_contracts.keys() & current_contracts.keys()
        if previous_contracts[identifier] == current_contracts[identifier]
    )

    next_history: dict[str, Any] = {}
    reset_counts: dict[str, int] = {}
    for identifier in sorted(current_contracts):
        previous = history.get(identifier)
        if identifier in unchanged:
            require(isinstance(previous, dict), f"missing retained history for {identifier}")
            next_history[identifier] = previous
            continue
        if isinstance(previous, dict):
            buckets = previous.get("buckets")
            reset_counts[identifier] = len(buckets) if isinstance(buckets, list) else 0
        else:
            reset_counts[identifier] = 0
        next_history[identifier] = empty_surface_history()

    migrated = dict(state)
    migrated["surface_history"] = next_history
    details = {
        "changed": changed,
        "added": added,
        "removed": removed,
        "unchanged": unchanged,
        "reset_bucket_counts": reset_counts,
        "previous_contracts": previous_contracts,
        "current_contracts": current_contracts,
    }
    return migrated, details


def apply_registered_migration(
    state: Mapping[str, Any],
    entry: Mapping[str, Any],
    previous_manifest: Mapping[str, Any],
    current_manifest: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Apply one exact reviewed retroactive migration idempotently."""
    migration_id = entry.get("id")
    require(isinstance(migration_id, str) and MIGRATION_ID.fullmatch(migration_id), "migration id is invalid")
    reset_surfaces_raw = entry.get("reset_surfaces")
    require(isinstance(reset_surfaces_raw, list) and reset_surfaces_raw, "migration reset_surfaces is invalid")
    reset_surfaces = sorted(reset_surfaces_raw)
    require(len(reset_surfaces) == len(set(reset_surfaces)), "migration reset surfaces contain duplicates")
    require(all(isinstance(item, str) for item in reset_surfaces), "migration surface id is invalid")

    previous_contracts = contract_map(previous_manifest)
    current_contracts = contract_map(current_manifest)
    changed = sorted(
        identifier
        for identifier in previous_contracts.keys() & current_contracts.keys()
        if previous_contracts[identifier] != current_contracts[identifier]
    )
    added = sorted(current_contracts.keys() - previous_contracts.keys())
    removed = sorted(previous_contracts.keys() - current_contracts.keys())
    require(not added and not removed, "retroactive migration may not change the surface set")
    require(changed == reset_surfaces, "registered reset surfaces do not equal changed contracts")

    history = state.get("surface_history")
    require(isinstance(history, dict), "persisted SLO history is invalid")
    next_history = dict(history)
    reset_counts: dict[str, int] = {}
    for identifier in reset_surfaces:
        previous = history.get(identifier)
        require(isinstance(previous, dict), f"missing retained history for {identifier}")
        buckets = previous.get("buckets")
        reset_counts[identifier] = len(buckets) if isinstance(buckets, list) else 0
        next_history[identifier] = empty_surface_history()

    migrated = dict(state)
    migrated["surface_history"] = next_history
    return migrated, {
        "migration_id": migration_id,
        "changed": changed,
        "added": added,
        "removed": removed,
        "unchanged": sorted(current_contracts.keys() - set(reset_surfaces)),
        "reset_bucket_counts": reset_counts,
        "previous_contracts": previous_contracts,
        "current_contracts": current_contracts,
    }


def replace_embedded_state(body: str, state: Mapping[str, Any]) -> str:
    require(isinstance(body, str), "SLO state issue body is invalid")
    start = body.find(STATE_BEGIN)
    end = body.find(STATE_END)
    require(start >= 0 and end > start, "SLO state markers are missing or invalid")
    return body[: start + len(STATE_BEGIN)] + encode_state(state) + body[end:]


def load_registry(path: Path) -> list[dict[str, Any]]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContractError("history migration registry is unavailable or invalid") from exc
    require(isinstance(raw, dict) and raw.get("schema") == REGISTRY_SCHEMA, "history migration registry schema is invalid")
    entries = raw.get("migrations")
    require(isinstance(entries, list), "history migration registry entries are invalid")
    seen: set[str] = set()
    normalized: list[dict[str, Any]] = []
    for raw_entry in entries:
        require(isinstance(raw_entry, dict), "history migration registry entry is invalid")
        entry = dict(raw_entry)
        migration_id = entry.get("id")
        require(isinstance(migration_id, str) and MIGRATION_ID.fullmatch(migration_id), "migration id is invalid")
        require(migration_id not in seen, "duplicate migration id")
        seen.add(migration_id)
        for key in ("from_manifest_revision", "to_manifest_revision"):
            revision = entry.get(key)
            require(isinstance(revision, str) and SHA40.fullmatch(revision), f"{migration_id} {key} is invalid")
        reset_surfaces = entry.get("reset_surfaces")
        require(isinstance(reset_surfaces, list) and reset_surfaces, f"{migration_id} reset surfaces are invalid")
        require(all(isinstance(item, str) and item for item in reset_surfaces), f"{migration_id} reset surface is invalid")
        require(len(reset_surfaces) == len(set(reset_surfaces)), f"{migration_id} reset surfaces duplicate")
        reason = entry.get("reason")
        require(isinstance(reason, str) and 8 <= len(reason) <= 500, f"{migration_id} reason is invalid")
        normalized.append(entry)
    return normalized


def empty_marker_state() -> dict[str, Any]:
    return {"schema": MARKER_SCHEMA, "updated_at": None, "applied": []}


def parse_marker_state(body: Any) -> dict[str, Any]:
    if body is None:
        return empty_marker_state()
    require(isinstance(body, str), "migration marker issue body is invalid")
    start = body.find(MARKER_BEGIN)
    end = body.find(MARKER_END)
    require(start >= 0 and end > start, "migration marker state is missing")
    try:
        value = json.loads(body[start + len(MARKER_BEGIN) : end])
    except json.JSONDecodeError as exc:
        raise ContractError("migration marker state is invalid JSON") from exc
    require(isinstance(value, dict) and value.get("schema") == MARKER_SCHEMA, "migration marker schema is invalid")
    applied = value.get("applied")
    require(isinstance(applied, list), "migration marker applied list is invalid")
    seen: set[str] = set()
    for row in applied:
        require(isinstance(row, dict), "migration marker row is invalid")
        migration_id = row.get("id")
        require(isinstance(migration_id, str) and MIGRATION_ID.fullmatch(migration_id), "migration marker id is invalid")
        require(migration_id not in seen, "migration marker id is duplicated")
        seen.add(migration_id)
        require(isinstance(row.get("applied_at"), str), "migration marker timestamp is invalid")
        require(isinstance(row.get("state_sha256"), str) and len(row["state_sha256"]) == 64, "migration marker state digest is invalid")
    return value


def marker_body(state: Mapping[str, Any]) -> str:
    payload = canonical_json(state).decode("utf-8")
    return "\n".join(
        [
            "# SZL Autonomic SLO History Migrations",
            "",
            "Machine-managed replay fence for reviewed reliability-history migrations.",
            "It contains migration IDs and public state digests only; no response bodies or secrets.",
            "",
            MARKER_BEGIN + payload + MARKER_END,
            "",
        ]
    )


def require_verified_commit(github: GitHubApi, repository: str, revision: str) -> None:
    require(bool(SHA40.fullmatch(revision)), "historical manifest revision is invalid")
    value = github.request("GET", f"/repos/{repository}/commits/{revision}")
    require(isinstance(value, dict), "historical manifest commit is unavailable")
    commit = value.get("commit")
    verification = commit.get("verification") if isinstance(commit, dict) else None
    require(
        isinstance(verification, dict) and verification.get("verified") is True,
        "historical manifest commit is not cryptographically verified",
    )


def policy_for_historical_manifest(
    policy: Mapping[str, Any], raw_manifest: Mapping[str, Any]
) -> dict[str, Any]:
    """Validate an older asset set without weakening its normal surface checks."""
    raw_surfaces = list(raw_manifest.get("platforms") or []) + list(raw_manifest.get("public_products") or [])
    repositories: list[str] = []
    for surface in raw_surfaces:
        require(isinstance(surface, dict), "historical manifest surface is invalid")
        repository = surface.get("hf_repository")
        require(isinstance(repository, str) and repository, "historical HF repository is invalid")
        repositories.append(repository)
    historical = dict(policy)
    historical["allowed_hf_repositories"] = sorted(repositories)
    return historical


def historical_manifest(
    github: GitHubApi,
    policy: Mapping[str, Any],
    revision: str,
) -> tuple[dict[str, Any], str]:
    require_verified_commit(github, policy["source_manifest"]["repository"], revision)
    raw_bytes = github.file_at(
        policy["source_manifest"]["repository"],
        policy["source_manifest"]["path"],
        revision,
    )
    try:
        raw = json.loads(raw_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContractError("historical manifest is not valid UTF-8 JSON") from exc
    require(isinstance(raw, dict), "historical manifest must be an object")
    validated = validate_manifest(raw, policy=policy_for_historical_manifest(policy, raw))
    return validated, sha256_hex(canonical_json(raw))


def run_migration(
    *,
    policy_path: Path,
    registry_path: Path,
    output: Path,
    dry_run: bool,
) -> int:
    policy, policy_sha256 = load_policy(policy_path)
    registry = load_registry(registry_path)
    registry_sha256 = sha256_hex(registry_path.read_bytes())
    token = (os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN") or "").strip() or None
    require(bool(token), "GITHUB_TOKEN is required for durable SLO state migration")
    github = GitHubApi(
        token=token,
        repository=policy["controller_repository"],
        timeout=policy["probe"]["timeout_seconds"],
    )
    controller_tip = github.verified_tip(policy["controller_repository"], policy["controller_branch"])
    workflow_sha = os.getenv("GITHUB_SHA", "").strip()
    if workflow_sha:
        require(workflow_sha == controller_tip, "migration is not running from exact verified main")

    current_manifest, current_revision, current_manifest_sha256 = load_signed_manifest(github, policy)
    state_issue = github.find_open_issue(policy["state_issue"]["title"])
    marker_issue = github.find_open_issue(MARKER_TITLE)
    marker_state = parse_marker_state(marker_issue.get("body") if marker_issue else None)
    applied_ids = {row["id"] for row in marker_state["applied"]}
    receipt: dict[str, Any] = {
        "schema": MIGRATION_SCHEMA,
        "generated_at": utc_now(),
        "controller_revision": controller_tip,
        "policy_sha256": policy_sha256,
        "registry_sha256": registry_sha256,
        "current_manifest_revision": current_revision,
        "current_manifest_sha256": current_manifest_sha256,
        "state_issue_present": state_issue is not None,
        "marker_issue_present": marker_issue is not None,
        "mutation_requested": not dry_run,
        "mutation_performed": False,
        "applied_migrations": [],
        "authority": {
            "issue_state_only": True,
            "service_restart": False,
            "workflow_dispatch": False,
            "source_write": False,
            "dns_mutation": False,
            "provider_mutation": False,
            "product_action": False,
            "arbitrary_shell": False,
        },
        "secret_values_recorded": False,
    }

    if state_issue is None:
        receipt["status"] = "NO_STATE_ISSUE"
        write_json_atomic(output, receipt)
        return 0

    body = state_issue.get("body")
    require(isinstance(body, str), "existing SLO state issue has no body")
    state = extract_state(body)
    original_state_sha256 = sha256_hex(canonical_json(state))
    receipt["state_sha256_before"] = original_state_sha256

    # Apply reviewed retroactive migrations even when an older controller already
    # advanced the manifest revision before this migration step was introduced.
    pending_entries = [
        entry
        for entry in registry
        if entry["to_manifest_revision"] == current_revision and entry["id"] not in applied_ids
    ]
    working_state = dict(state)
    applied_rows: list[dict[str, Any]] = []
    for entry in pending_entries:
        require_verified_commit(github, policy["source_manifest"]["repository"], entry["to_manifest_revision"])
        previous_manifest, previous_sha256 = historical_manifest(
            github, policy, entry["from_manifest_revision"]
        )
        working_state, details = apply_registered_migration(
            working_state, entry, previous_manifest, current_manifest
        )
        applied_rows.append(
            {
                "id": entry["id"],
                "from_manifest_revision": entry["from_manifest_revision"],
                "to_manifest_revision": entry["to_manifest_revision"],
                "previous_manifest_sha256": previous_sha256,
                "reset_bucket_counts": details["reset_bucket_counts"],
                "changed": details["changed"],
                "unchanged": details["unchanged"],
            }
        )

    # Normal forward migration remains generic when state still identifies the old
    # manifest and no reviewed retroactive migration handled the transition.
    previous_revision = working_state.get("manifest_revision")
    receipt["previous_manifest_revision"] = previous_revision
    forward_details: dict[str, Any] | None = None
    if not applied_rows and previous_revision != current_revision:
        require(isinstance(previous_revision, str), "persisted manifest revision is unavailable")
        previous_manifest, previous_sha256 = historical_manifest(github, policy, previous_revision)
        working_state, forward_details = migrate_history(
            working_state, previous_manifest, current_manifest
        )
        receipt["previous_manifest_sha256"] = previous_sha256
        receipt["forward_migration"] = forward_details

    if not applied_rows and forward_details is None:
        receipt["status"] = "CURRENT_CONTRACT"
        receipt["state_sha256_after"] = original_state_sha256
        write_json_atomic(output, receipt)
        return 0

    after_sha256 = sha256_hex(canonical_json(working_state))
    receipt["state_sha256_after"] = after_sha256
    receipt["applied_migrations"] = applied_rows
    receipt["status"] = "DRY_RUN" if dry_run else "MIGRATED"
    if not dry_run:
        # Write the corrected reliability state first. If the replay fence write
        # fails, the next run safely repeats the idempotent reset rather than
        # recording a migration that was never applied.
        github.update_issue(
            state_issue,
            body=replace_embedded_state(body, working_state),
            state="open",
        )
        now = utc_now()
        next_marker_state = dict(marker_state)
        next_marker_state["updated_at"] = now
        next_applied = list(marker_state["applied"])
        for row in applied_rows:
            next_applied.append(
                {
                    "id": row["id"],
                    "applied_at": now,
                    "state_sha256": after_sha256,
                }
            )
        next_marker_state["applied"] = next_applied
        if marker_issue is None:
            github.create_issue(title=MARKER_TITLE, body=marker_body(next_marker_state))
        else:
            github.update_issue(marker_issue, body=marker_body(next_marker_state), state="open")
        receipt["mutation_performed"] = True
        receipt["state_issue_number"] = state_issue.get("number")
    write_json_atomic(output, receipt)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, default=Path("autonomic/slo_policy.json"))
    parser.add_argument(
        "--registry",
        type=Path,
        default=Path("autonomic/slo_history_migrations.json"),
    )
    parser.add_argument(
        "--output", type=Path, default=Path("reports/autonomic-slo-history-migration.json")
    )
    parser.add_argument("--dry-run", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return run_migration(
            policy_path=args.policy,
            registry_path=args.registry,
            output=args.output,
            dry_run=args.dry_run,
        )
    except Exception as exc:
        failure = {
            "schema": MIGRATION_SCHEMA,
            "generated_at": utc_now(),
            "status": "FAILED",
            "error_kind": type(exc).__name__.upper()[:64],
            "error": "history migration failed closed",
            "mutation_performed": False,
            "secret_values_recorded": False,
        }
        try:
            write_json_atomic(args.output, failure)
        except Exception:
            pass
        print(json.dumps(failure, sort_keys=True), file=os.sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
