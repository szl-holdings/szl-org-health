#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fail-closed source-only model proof axes for an existing SZL HF census.

Does not query the Hub, import weights, execute a trainer, or authorize release.
A repository named '*-trained' is not training evidence. A safetensors name
is not a checksum, successful fine-tune, checkpoint restoration, or quality gate.
"""
from __future__ import annotations

import argparse
from collections import Counter
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import sys
from typing import Any

SCHEMA = "szl.hf-model-proof-axes/v1"
ORG = "SZLHOLDINGS"
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
MODEL_ID = re.compile(r"SZLHOLDINGS/[A-Za-z0-9][A-Za-z0-9_.-]*\Z")
NON_TRAINING_CONTRACTS = {"huggingface-kernel", "operational-payload"}
MAX_INPUT_BYTES = 12_000_000


class ProofHold(ValueError):
    """Stable public reason code, never caller-supplied text or file paths."""


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise ProofHold(reason)


def _status(row: dict[str, Any], scope: str) -> tuple[str, str]:
    model_id = row.get("id")
    if not isinstance(model_id, str) or not MODEL_ID.fullmatch(model_id):
        return "UNKNOWN", "INVALID_MODEL_ID"
    if scope == "public" and row.get("private") is not False:
        return "UNKNOWN", "VISIBILITY_NOT_PUBLICLY_PROVED"
    if type(row.get("private")) is not bool:
        return "UNKNOWN", "VISIBILITY_UNAVAILABLE"
    if not isinstance(row.get("sha"), str) or not SHA40.fullmatch(row["sha"]):
        return "UNKNOWN", "IMMUTABLE_MODEL_REVISION_UNAVAILABLE"
    contract = row.get("contract")
    if not isinstance(contract, str) or not contract:
        return "UNKNOWN", "ARTIFACT_CONTRACT_UNAVAILABLE"
    if contract in NON_TRAINING_CONTRACTS or contract.startswith("kernel-"):
        # A non-training label cannot bypass contradictory or unobserved
        # model-weight evidence. This is classification, not model execution.
        files = row.get("weight_files_observed")
        if not isinstance(files, list) or any(not isinstance(x, str) for x in files):
            return "UNKNOWN", "NON_TRAINING_CONTRACT_WEIGHT_UNOBSERVED"
        if files or row.get("weight_state") != "no-weight-file-observed":
            return "UNKNOWN", "NON_TRAINING_CONTRACT_WEIGHT_CONTRADICTION"
        return "NON_TRAINING_ARTIFACT", "MODEL_TRAINING_NOT_APPLICABLE"
    files = row.get("weight_files_observed")
    if not isinstance(files, list) or any(not isinstance(x, str) for x in files):
        return "UNKNOWN", "WEIGHT_FILE_OBSERVATION_UNAVAILABLE"
    declared = row.get("weight_state")
    if declared not in {"weights-present", "no-weight-file-observed", "unknown"}:
        return "UNKNOWN", "WEIGHT_STATE_UNRECOGNIZED"
    if (bool(files)) != (declared == "weights-present"):
        if declared != "unknown" or files:
            return "UNKNOWN", "WEIGHT_STATE_CONTRADICTION"
    artifact = row.get("artifact_state")
    if artifact == "unknown" or not isinstance(artifact, str):
        return "UNKNOWN", "ARTIFACT_OBSERVATION_UNAVAILABLE"
    if files:
        return "WEIGHT_ARTIFACT_UNQUALIFIED", "TRAINING_EVALUATION_AND_RIGHTS_UNVERIFIED"
    if artifact in {"artifact-present", "payload-manifest-verified"}:
        return "NON_WEIGHT_ARTIFACT_UNQUALIFIED", "NON_WEIGHT_ARTIFACT_NOT_TRAINING_PROOF"
    if declared == "no-weight-file-observed" and artifact in {
        "no-model-artifact-observed", "not-required-by-contract", "payload-manifest-incomplete"
    }:
        return "NO_WEIGHT_FILE_OBSERVED", "NO_WEIGHT_ARTIFACT_IN_REPOSITORY_LISTING"
    return "UNKNOWN", "ARTIFACT_CLASSIFICATION_UNDETERMINED"


def evaluate(snapshot: dict[str, Any], *, scope: str, source_revision: str) -> dict[str, Any]:
    _require(scope in {"public", "authenticated"}, "INVALID_SCOPE")
    _require(isinstance(source_revision, str) and bool(SHA40.fullmatch(source_revision)),
             "SOURCE_REVISION_UNAVAILABLE")
    _require(isinstance(snapshot, dict), "INVALID_SNAPSHOT")
    hf = snapshot.get("huggingface", snapshot)
    _require(isinstance(hf, dict) and hf.get("organization") == ORG,
             "HF_ORGANIZATION_MISMATCH")
    assets = hf.get("assets")
    _require(isinstance(assets, dict), "HF_ASSETS_UNAVAILABLE")
    models = assets.get("models")
    _require(isinstance(models, dict) and models.get("ok") is True
             and models.get("partial") is False, "MODEL_CENSUS_INCOMPLETE")
    rows = models.get("items")
    _require(isinstance(rows, list) and type(models.get("count")) is int
             and models["count"] == len(rows), "MODEL_DENOMINATOR_MISMATCH")
    _require(len(rows) <= 2000, "MODEL_ITEM_BUDGET")
    # A public census must not silently count private or unverifiable model rows.
    # Classification as UNKNOWN would still reveal their presence in aggregates.
    if scope == "public" and any(
        isinstance(item, dict) and item.get("private") is not False for item in rows
    ):
        raise ProofHold("PUBLIC_SCOPE_VISIBILITY_UNPROVEN")
    seen: set[str] = set()
    counts: Counter[str] = Counter()
    reasons: Counter[str] = Counter()
    badges = []
    license_metadata_absent = 0
    license_metadata_unknown = 0
    pipeline_tag_missing = 0
    for row in rows:
        if not isinstance(row, dict):
            status, reason, identifier = "UNKNOWN", "MALFORMED_MODEL_ROW", None
        else:
            identifier = row.get("id") if isinstance(row.get("id"), str) else None
            if identifier is not None and identifier in seen:
                raise ProofHold("DUPLICATE_MODEL_ID")
            if identifier is not None:
                seen.add(identifier)
            status, reason = _status(row, scope)
            license_tag = row.get("license_declared")
            if license_tag is False:
                license_metadata_absent += 1
            elif license_tag is not True:
                license_metadata_unknown += 1
            if not isinstance(row.get("pipeline_tag"), str) or not row["pipeline_tag"].strip():
                pipeline_tag_missing += 1
        counts[status] += 1
        reasons[reason] += 1
        # These rows belong only in an explicitly owner-private evidence artifact.
        badges.append({"id": identifier, "state": status, "reason": reason,
                       "model_revision": row.get("sha") if isinstance(row, dict)
                       and isinstance(row.get("sha"), str) and SHA40.fullmatch(row["sha"])
                       else None})
    _require(sum(counts.values()) == len(rows), "COVERAGE_IDENTITY_FAILED")
    return {
        "schema": SCHEMA, "source_organization": ORG, "scope": scope,
        "census_source_revision": source_revision,
        "repository_count": len(rows), "status_counts": dict(sorted(counts.items())),
        "reason_counts": dict(sorted(reasons.items())),
        "license_metadata_absent": license_metadata_absent,
        "license_metadata_unknown": license_metadata_unknown,
        "pipeline_tag_missing": pipeline_tag_missing,
        "training_verified_count": 0,
        "evaluation_verified_count": 0,
        "production_qualified_count": 0,
        "training_and_release_authorized": False,
        "model_quality_checked": False,
        "model_training_state": "UNVERIFIED_FOR_ALL_REPOSITORIES",
        "evidence_is_signature": False,
        "per_repository_private": badges,
    }


def _strict_object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject ambiguous JSON at any depth before evaluating proof axes."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProofHold("DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", required=True, type=Path)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--scope", required=True, choices=("public", "authenticated"))
    parser.add_argument("--private-receipt", type=Path)
    args = parser.parse_args(argv)
    try:
        _require(args.snapshot.stat().st_size <= MAX_INPUT_BYTES, "SNAPSHOT_BYTE_BUDGET")
        raw = args.snapshot.read_bytes()
        _require(len(raw) <= MAX_INPUT_BYTES, "SNAPSHOT_BYTE_BUDGET")
        data = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_strict_object_pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(ProofHold("NONFINITE_JSON")),
        )
        report = evaluate(data, scope=args.scope, source_revision=args.source_revision)
        report["snapshot_sha256"] = sha256(raw).hexdigest()
        report_bytes = (json.dumps(report, sort_keys=True, separators=(",", ":"),
                                   allow_nan=False) + "\n").encode("utf-8")
        receipt_hash = None
        if args.private_receipt is not None:
            with args.private_receipt.open("xb") as fd:
                fd.write(report_bytes)
                fd.flush()
                os.fsync(fd.fileno())
            _require(args.private_receipt.read_bytes() == report_bytes,
                     "RECEIPT_READBACK_MISMATCH")
            receipt_hash = sha256(report_bytes).hexdigest()
        public = {k: v for k, v in report.items() if k != "per_repository_private"}
        public["private_receipt_sha256"] = receipt_hash
        print(json.dumps(public, sort_keys=True))
        return 0
    except ProofHold as exc:
        print(json.dumps({"state": "HOLD", "reason": str(exc),
                          "training_and_release_authorized": False}))
        return 78
    except (OSError, UnicodeError, ValueError, RecursionError):
        print(json.dumps({"state": "HOLD", "reason": "SNAPSHOT_OR_RECEIPT_UNAVAILABLE",
                          "training_and_release_authorized": False}))
        return 78


if __name__ == "__main__":
    sys.exit(main())
