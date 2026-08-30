#!/usr/bin/env python3
"""Fail-closed validator for the SZL Estate v10 execution ledger.

This tool validates control-plane state only. It never mutates GitHub,
Hugging Face, deployments, repositories, models, datasets, kernels or Spaces.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

EXPECTED_COUNTS = {
    "github_repositories": 98,
    "github_target_keep_active_public": 20,
    "github_target_migrate_then_archive": 39,
    "github_archived": 34,
    "github_private": 5,
    "hf_models": 43,
    "hf_datasets": 28,
    "hf_kernels": 14,
    "hf_spaces": 7,
    "hf_collections": 18,
    "hf_buckets": 1,
}
REQUIRED_AUTHORITIES = {
    "commercial_product": "a11oy",
    "product_foundation": "platform",
    "proof_front": "a11oy-net",
    "model_authority": "szl-forge",
    "kernel_authority": "szl-kernels",
    "evidence_authority": "szl-lake",
    "private_mutation_authority": "szl-org-health",
}
ALLOWED_GATE_STATUS = {
    "NOT_STARTED",
    "IN_PROGRESS",
    "BLOCKED",
    "BLOCKED_BY_G0_G1",
    "BLOCKED_BY_G0_G1_G2",
    "BLOCKED_BY_G3_G4",
    "BLOCKED_BY_G1_G3_G4",
    "IN_PROGRESS_PRIVATE_EVIDENCE_REQUIRED",
    "PASS",
}
FORBIDDEN_TRUE = {
    "force_merge",
    "archive_before_parity",
    "unsupported_model_promotion",
    "controller_mutation_authority",
}


class ValidationError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(message)


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValidationError(f"missing state file: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValidationError(f"invalid JSON in {path}: {exc}") from exc
    require(isinstance(value, dict), "state root must be an object")
    return value


def validate_state(state: dict[str, Any]) -> list[str]:
    notes: list[str] = []
    require(state.get("schema_version") == "1.0", "unsupported schema_version")
    require(state.get("program") == "SZL Estate v10", "unexpected program")
    require(state.get("control_authority") == "szl-holdings/szl-org-health",
            "wrong control authority")
    require(state.get("status") in {"IN_PROGRESS", "PASS", "BLOCKED"},
            "invalid program status")

    doctrine = state.get("doctrine")
    require(isinstance(doctrine, dict), "doctrine must be an object")
    require(doctrine.get("protected_prs_only") is True,
            "protected_prs_only must remain true")
    for key in FORBIDDEN_TRUE:
        require(doctrine.get(key) is False, f"{key} must remain false")

    counts = state.get("seed_counts")
    require(isinstance(counts, dict), "seed_counts must be an object")
    for key, expected in EXPECTED_COUNTS.items():
        require(counts.get(key) == expected,
                f"seed count drift for {key}: expected {expected}, got {counts.get(key)!r}")

    architecture = state.get("target_architecture")
    require(isinstance(architecture, dict), "target_architecture must be an object")
    for key, expected in REQUIRED_AUTHORITIES.items():
        require(architecture.get(key) == expected,
                f"canonical authority mismatch for {key}")

    gates = state.get("gates")
    require(isinstance(gates, list) and len(gates) == 8,
            "exactly G0..G7 must be present")
    gate_ids = [gate.get("id") for gate in gates if isinstance(gate, dict)]
    require(gate_ids == [f"G{i}" for i in range(8)],
            "gates must be ordered G0 through G7")
    for gate in gates:
        require(gate.get("status") in ALLOWED_GATE_STATUS,
                f"invalid status for {gate.get('id')}")

    blockers = state.get("live_blockers")
    require(isinstance(blockers, list), "live_blockers must be a list")
    blocker_ids = set()
    for blocker in blockers:
        require(isinstance(blocker, dict), "blocker must be an object")
        blocker_id = blocker.get("id")
        require(isinstance(blocker_id, str) and blocker_id, "blocker id missing")
        require(blocker_id not in blocker_ids, f"duplicate blocker {blocker_id}")
        blocker_ids.add(blocker_id)
        require(blocker.get("status") not in {"PASS", "GREEN"},
                f"resolved blocker {blocker_id} must leave live_blockers")
        require(bool(blocker.get("reason")), f"blocker {blocker_id} lacks reason")
        require(bool(blocker.get("required_next")),
                f"blocker {blocker_id} lacks required_next")

    destructive = state.get("destructive_actions")
    require(isinstance(destructive, dict), "destructive_actions must be an object")
    for key in (
        "repositories_archived_this_program",
        "models_deleted",
        "datasets_deleted",
        "spaces_deleted",
    ):
        value = destructive.get(key)
        require(isinstance(value, list), f"{key} must be a list")
        require(not value,
                f"{key} is nonempty before migration/parity/readback admission")

    ledger = state.get("mutation_ledger")
    require(isinstance(ledger, list) and ledger,
            "mutation_ledger must contain at least one entry")
    seen = set()
    for entry in ledger:
        require(isinstance(entry, dict), "ledger entry must be an object")
        entry_id = entry.get("id")
        require(isinstance(entry_id, str) and entry_id, "ledger id missing")
        require(entry_id not in seen, f"duplicate ledger id {entry_id}")
        seen.add(entry_id)
        require(bool(entry.get("target")), f"{entry_id} target missing")
        require(bool(entry.get("operation")), f"{entry_id} operation missing")
        require(bool(entry.get("status")), f"{entry_id} status missing")
        require(bool(entry.get("evidence")), f"{entry_id} evidence missing")

    notes.append(f"validated {len(gates)} gates")
    notes.append(f"validated {len(blockers)} live blockers")
    notes.append(f"validated {len(ledger)} mutation-ledger entries")
    notes.append("destructive-action lists are empty and fail-closed")
    return notes


def self_test() -> None:
    sample = {
        "schema_version": "1.0",
        "program": "SZL Estate v10",
        "control_authority": "szl-holdings/szl-org-health",
        "status": "IN_PROGRESS",
        "doctrine": {
            "commercial_product": "a11oy",
            "protected_prs_only": True,
            "force_merge": False,
            "archive_before_parity": False,
            "unsupported_model_promotion": False,
            "controller_mutation_authority": False,
        },
        "seed_counts": EXPECTED_COUNTS.copy(),
        "target_architecture": REQUIRED_AUTHORITIES.copy(),
        "gates": [
            {"id": f"G{i}", "name": f"gate-{i}", "status": "IN_PROGRESS"}
            for i in range(8)
        ],
        "live_blockers": [],
        "mutation_ledger": [{
            "id": "MUT-TEST",
            "target": "test",
            "operation": "VALIDATE",
            "status": "PASS",
            "evidence": "self-test",
        }],
        "destructive_actions": {
            "repositories_archived_this_program": [],
            "models_deleted": [],
            "datasets_deleted": [],
            "spaces_deleted": [],
        },
    }
    validate_state(sample)

    unsafe = json.loads(json.dumps(sample))
    unsafe["doctrine"]["force_merge"] = True
    try:
        validate_state(unsafe)
    except ValidationError:
        pass
    else:
        raise ValidationError("self-test failed to reject force_merge=true")

    unsafe = json.loads(json.dumps(sample))
    unsafe["destructive_actions"]["repositories_archived_this_program"] = ["x"]
    try:
        validate_state(unsafe)
    except ValidationError:
        pass
    else:
        raise ValidationError("self-test failed to reject premature archive")

    print("estate-v10 self-test: PASS")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--state",
        type=Path,
        default=Path("execution/estate-v10/EXECUTION_STATE.json"),
    )
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    try:
        if args.self_test:
            self_test()
            return 0
        state = load_json(args.state)
        notes = validate_state(state)
    except ValidationError as exc:
        print(f"estate-v10 validation: FAIL: {exc}", file=sys.stderr)
        return 1

    print("estate-v10 validation: PASS")
    for note in notes:
        print(f"- {note}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
