#!/usr/bin/env python3
"""Segment retained SLO history when a declared probe contract changes.

Availability history is meaningful only for one stable monitoring predicate. This
migration compares the exact previously admitted public-estate manifest with the
current verified manifest and resets history only for surfaces whose monitored
origin or required-path contract changed. Unchanged surfaces retain every sample.

The module mutates only the machine-managed SLO state issue. It cannot restart a
service, dispatch a workflow, modify product source, change DNS, or touch provider
state.
"""

from __future__ import annotations

import argparse
import json
import os
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

MIGRATION_SCHEMA = "szl.autonomic-slo-history-migration/v1"


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
    """Reset only added/changed predicates; preserve unchanged history exactly."""
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


def replace_embedded_state(body: str, state: Mapping[str, Any]) -> str:
    require(isinstance(body, str), "SLO state issue body is invalid")
    start = body.find(STATE_BEGIN)
    end = body.find(STATE_END)
    require(start >= 0 and end > start, "SLO state markers are missing or invalid")
    return body[: start + len(STATE_BEGIN)] + encode_state(state) + body[end:]


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
    raw_surfaces = list(raw_manifest.get("platforms") or []) + list(
        raw_manifest.get("public_products") or []
    )
    repositories: list[str] = []
    for surface in raw_surfaces:
        require(isinstance(surface, dict), "historical manifest surface is invalid")
        repository = surface.get("hf_repository")
        require(isinstance(repository, str) and repository, "historical HF repository is invalid")
        repositories.append(repository)
    historical = dict(policy)
    historical["allowed_hf_repositories"] = sorted(repositories)
    return historical


def run_migration(*, policy_path: Path, output: Path, dry_run: bool) -> int:
    policy, policy_sha256 = load_policy(policy_path)
    token = (os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN") or "").strip() or None
    require(bool(token), "GITHUB_TOKEN is required for durable SLO state migration")
    github = GitHubApi(
        token=token,
        repository=policy["controller_repository"],
        timeout=policy["probe"]["timeout_seconds"],
    )
    controller_tip = github.verified_tip(
        policy["controller_repository"], policy["controller_branch"]
    )
    workflow_sha = os.getenv("GITHUB_SHA", "").strip()
    if workflow_sha:
        require(workflow_sha == controller_tip, "migration is not running from exact verified main")

    current_manifest, current_revision, current_manifest_sha256 = load_signed_manifest(
        github, policy
    )
    state_issue = github.find_open_issue(policy["state_issue"]["title"])
    receipt: dict[str, Any] = {
        "schema": MIGRATION_SCHEMA,
        "generated_at": utc_now(),
        "controller_revision": controller_tip,
        "policy_sha256": policy_sha256,
        "current_manifest_revision": current_revision,
        "current_manifest_sha256": current_manifest_sha256,
        "state_issue_present": state_issue is not None,
        "mutation_requested": not dry_run,
        "mutation_performed": False,
        "changed": [],
        "added": [],
        "removed": [],
        "unchanged": [],
        "reset_bucket_counts": {},
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
    previous_revision = state.get("manifest_revision")
    receipt["previous_manifest_revision"] = previous_revision
    if previous_revision == current_revision:
        receipt["status"] = "CURRENT_CONTRACT"
        write_json_atomic(output, receipt)
        return 0
    require(isinstance(previous_revision, str), "persisted manifest revision is unavailable")
    require_verified_commit(
        github, policy["source_manifest"]["repository"], previous_revision
    )
    previous_bytes = github.file_at(
        policy["source_manifest"]["repository"],
        policy["source_manifest"]["path"],
        previous_revision,
    )
    try:
        previous_raw = json.loads(previous_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContractError("historical manifest is not valid UTF-8 JSON") from exc
    require(isinstance(previous_raw, dict), "historical manifest must be an object")
    previous_manifest = validate_manifest(
        previous_raw,
        policy=policy_for_historical_manifest(policy, previous_raw),
    )
    receipt["previous_manifest_sha256"] = sha256_hex(canonical_json(previous_raw))

    migrated, details = migrate_history(state, previous_manifest, current_manifest)
    receipt.update(details)
    affected = details["changed"] + details["added"] + details["removed"]
    if not affected:
        receipt["status"] = "CONTRACT_BYTES_UNCHANGED"
        write_json_atomic(output, receipt)
        return 0

    receipt["status"] = "DRY_RUN" if dry_run else "MIGRATED"
    if not dry_run:
        migrated_body = replace_embedded_state(body, migrated)
        github.update_issue(state_issue, body=migrated_body, state="open")
        receipt["mutation_performed"] = True
        receipt["state_issue_number"] = state_issue.get("number")
    write_json_atomic(output, receipt)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, default=Path("autonomic/slo_policy.json"))
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
